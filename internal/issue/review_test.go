package issue

import (
	"context"
	"testing"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	authz "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	kt "k8s.io/client-go/testing"
)

func TestEffectivePermissionBoundaries(t *testing.T) {
	c := config.Cluster{IdentityNamespace: "identity", Provider: config.Provider{ServiceAccount: &config.ServiceAccount{Name: "issuer"}}, Consumers: []config.Consumer{{ServiceAccount: config.ServiceAccount{Name: "ca"}}}}
	rule := func(group, resource, verb string, names ...string) authz.ResourceRule {
		return authz.ResourceRule{APIGroups: []string{group}, Resources: []string{resource}, Verbs: []string{verb}, ResourceNames: names}
	}
	for _, test := range []struct {
		name        string
		consumer    bool
		rules       []authz.ResourceRule
		nonresource []authz.NonResourceRule
		incomplete  bool
		accepted    bool
	}{
		{name: "issuer-exact-token", rules: []authz.ResourceRule{rule("", "serviceaccounts/token", "create", "ca")}, accepted: true},
		{name: "issuer-self-token", rules: []authz.ResourceRule{rule("", "serviceaccounts/token", "create", "issuer")}},
		{name: "issuer-unnamed-token", rules: []authz.ResourceRule{rule("", "serviceaccounts/token", "create")}},
		{name: "issuer-scheduling-read", rules: []authz.ResourceRule{rule("", "pods", "list")}},
		{name: "secret-list", rules: []authz.ResourceRule{rule("", "secrets", "list")}},
		{name: "consumer-secret-watch", consumer: true, rules: []authz.ResourceRule{rule("", "secrets", "watch")}},
		{name: "consumer-token", consumer: true, rules: []authz.ResourceRule{rule("", "serviceaccounts/token", "create", "ca")}},
		{name: "consumer-pod-delete", consumer: true, rules: []authz.ResourceRule{rule("", "pods", "delete")}},
		{name: "consumer-capi-patch", consumer: true, rules: []authz.ResourceRule{rule("cluster.x-k8s.io", "machinedeployments", "patch")}},
		{name: "consumer-read", consumer: true, rules: []authz.ResourceRule{rule("", "pods", "list"), rule("resource.k8s.io", "resourceclaims", "watch")}, accepted: true},
		{name: "consumer-events", consumer: true, rules: []authz.ResourceRule{rule("", "events", "create")}, accepted: true},
		{name: "named-identity", consumer: true, rules: []authz.ResourceRule{rule("", "serviceaccounts", "get", "ca")}, accepted: true},
		{name: "foreign-identity", consumer: true, rules: []authz.ResourceRule{rule("", "serviceaccounts", "get", "foreign")}},
		{name: "wildcard-verbs", rules: []authz.ResourceRule{rule("", "serviceaccounts/token", "*", "ca")}},
		{name: "wildcard-resource", consumer: true, rules: []authz.ResourceRule{rule("", "*", "get")}},
		{name: "incomplete", incomplete: true},
		{name: "public-discovery", nonresource: []authz.NonResourceRule{{Verbs: []string{"get"}, NonResourceURLs: []string{"/openid/v1/jwks", "/.well-known/openid-configuration", "/api/*"}}}, accepted: true},
		{name: "wildcard-url", nonresource: []authz.NonResourceRule{{Verbs: []string{"get"}, NonResourceURLs: []string{"*"}}}},
		{name: "nonresource-write", nonresource: []authz.NonResourceRule{{Verbs: []string{"post"}, NonResourceURLs: []string{"/api/*"}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := fake.NewClientset()
			client.PrependReactor("create", "selfsubjectrulesreviews", func(a kt.Action) (bool, runtime.Object, error) {
				if a.(kt.CreateAction).GetObject().(*authz.SelfSubjectRulesReview).Spec.Namespace != "identity" {
					t.Fatal("wrong review namespace")
				}
				return true, &authz.SelfSubjectRulesReview{Status: authz.SubjectRulesReviewStatus{ResourceRules: test.rules, NonResourceRules: test.nonresource, Incomplete: test.incomplete}}, nil
			})
			var consumer *config.Consumer
			if test.consumer {
				consumer = &c.Consumers[0]
			}
			if (reviewPermissions(context.Background(), client, c, consumer) == nil) != test.accepted {
				t.Fatal("permission boundary incorrect")
			}
		})
	}
}

func TestNamedLeasePermissionsRequireOptIn(t *testing.T) {
	consumer := config.Consumer{PermissionProfile: "ca-read-events-lease", LeaderElectionLease: &config.Ref{Namespace: "identity", Name: "ca-leader", UID: "lease-uid"}}
	for _, mode := range []string{"get", "update", "create", "delete", "patch", "list", "foreign", "unnamed", "legacy", "issuer"} {
		t.Run(mode, func(t *testing.T) {
			item := consumer
			verb, names := mode, []string{"ca-leader"}
			if mode == "foreign" {
				verb, names = "update", []string{"other"}
			}
			if mode == "unnamed" {
				verb, names = "update", nil
			}
			if mode == "legacy" {
				verb, item.PermissionProfile = "update", "ca-read-events"
			}
			if mode == "issuer" {
				verb = "update"
			}
			client := fake.NewClientset()
			client.PrependReactor("create", "selfsubjectrulesreviews", func(kt.Action) (bool, runtime.Object, error) {
				return true, &authz.SelfSubjectRulesReview{Status: authz.SubjectRulesReviewStatus{ResourceRules: []authz.ResourceRule{{APIGroups: []string{"coordination.k8s.io"}, Resources: []string{"leases"}, Verbs: []string{verb}, ResourceNames: names}}}}, nil
			})
			var candidate = &item
			if mode == "issuer" {
				candidate = nil
			}
			err := reviewPermissions(context.Background(), client, config.Cluster{IdentityNamespace: "identity"}, candidate)
			if (err == nil) != (mode == "get" || mode == "update") {
				t.Fatal("unexpected Lease authority accepted")
			}
		})
	}
}
