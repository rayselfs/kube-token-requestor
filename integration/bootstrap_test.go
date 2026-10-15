package integration

import (
	"encoding/json"
	"io"
	"os"
	"testing"

	rbac "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
)

func TestBootstrapHasNoWildcardOrUnrelatedWriteGrants(t *testing.T) {
	f, err := os.Open("../bootstrap/secret-issuer.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	decoder := yaml.NewYAMLOrJSONDecoder(f, 4096)
	tokenGrant := false
	for {
		var object struct {
			Kind      string                     `json:"kind"`
			Rules     []rbac.PolicyRule          `json:"rules"`
			Automount *bool                      `json:"automountServiceAccountToken"`
			Data      map[string]json.RawMessage `json:"data"`
		}
		if err := decoder.Decode(&object); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		switch object.Kind {
		case "Namespace", "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding":
		case "ServiceAccount":
			if object.Automount == nil || *object.Automount {
				t.Fatal("bootstrap account automount enabled")
			}
		default:
			t.Fatal("bootstrap must contain identities and grants only")
		}
		if len(object.Data) != 0 {
			t.Fatal("credential payload in bootstrap")
		}
		for _, rule := range object.Rules {
			for _, values := range [][]string{rule.APIGroups, rule.Resources, rule.Verbs, rule.ResourceNames} {
				for _, v := range values {
					if v == "*" {
						t.Fatal("wildcard grant")
					}
				}
			}
			if len(rule.NonResourceURLs) != 0 {
				t.Fatal("unexpected nonresource grant")
			}
			for _, resource := range rule.Resources {
				if resource == "secrets" {
					t.Fatal("secret access in child bootstrap")
				}
				for _, verb := range rule.Verbs {
					if verb == "get" || verb == "list" || verb == "watch" {
						continue
					}
					allowed := false
					if len(rule.APIGroups) == 1 {
						switch rule.APIGroups[0] {
						case "":
							allowed = resource == "events" && (verb == "create" || verb == "patch")
							if resource == "serviceaccounts/token" && verb == "create" && len(rule.ResourceNames) == 1 && rule.ResourceNames[0] == "ca-one" {
								allowed, tokenGrant = true, true
							}
						case "authentication.k8s.io":
							allowed = resource == "selfsubjectreviews" && verb == "create"
						case "authorization.k8s.io":
							allowed = (resource == "selfsubjectaccessreviews" || resource == "selfsubjectrulesreviews") && verb == "create"
						}
					}
					if !allowed {
						t.Fatal("unrelated child write grant")
					}
				}
			}
		}
	}
	if !tokenGrant {
		t.Fatal("missing exact consumer TokenRequest grant")
	}
}

func TestRenewalBootstrapGrantsOnlyNamedIssuerSelfMint(t *testing.T) {
	f, err := os.Open("../bootstrap/renewable-issuer-role.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	decoder := yaml.NewYAMLOrJSONDecoder(f, 4096)
	seenRole, seenBinding := false, false
	for {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		var kind struct {
			Kind string `json:"kind"`
		}
		if json.Unmarshal(raw, &kind) != nil {
			t.Fatal("invalid bootstrap")
		}
		switch kind.Kind {
		case "Role":
			var role rbac.Role
			_ = json.Unmarshal(raw, &role)
			if role.Namespace != "requestor-identity" || role.Name != "requestor-issuer-renewal" || len(role.Rules) != 1 {
				t.Fatal("unexpected renewal role")
			}
			r := role.Rules[0]
			if len(r.APIGroups) != 1 || r.APIGroups[0] != "" || len(r.Resources) != 1 || r.Resources[0] != "serviceaccounts/token" || len(r.ResourceNames) != 1 || r.ResourceNames[0] != "issuer" || len(r.Verbs) != 1 || r.Verbs[0] != "create" || len(r.NonResourceURLs) != 0 {
				t.Fatal("renewal grant broader than named self-mint")
			}
			seenRole = true
		case "RoleBinding":
			var binding rbac.RoleBinding
			_ = json.Unmarshal(raw, &binding)
			if binding.Namespace != "requestor-identity" || binding.RoleRef.Kind != "Role" || binding.RoleRef.Name != "requestor-issuer-renewal" || len(binding.Subjects) != 1 || binding.Subjects[0].Kind != "ServiceAccount" || binding.Subjects[0].Namespace != "requestor-identity" || binding.Subjects[0].Name != "issuer" {
				t.Fatal("renewal bound to unrelated subject")
			}
			seenBinding = true
		default:
			t.Fatal("renewal example must only grant named self-mint")
		}
	}
	if !seenRole || !seenBinding {
		t.Fatal("missing optional renewal grant/binding")
	}
}
