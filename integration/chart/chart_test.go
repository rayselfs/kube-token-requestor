package chart

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	yaml "k8s.io/apimachinery/pkg/util/yaml"
)

func render(t *testing.T, values map[string]any, args ...string) ([]map[string]any, error) {
	t.Helper()
	data, _ := json.Marshal(values)
	path := filepath.Join(t.TempDir(), "values.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("helm", append([]string{"template", "test", "../../charts/kube-token-requestor", "--namespace", "requestor-test", "-f", path}, args...)...)
	out, err := command.CombinedOutput()
	if err != nil {
		return nil, err
	}
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(out), 4096)
	objects := []map[string]any{}
	for {
		var object map[string]any
		if err := decoder.Decode(&object); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal("invalid rendered YAML")
		}
		if len(object) > 0 {
			objects = append(objects, object)
		}
	}
	return objects, nil
}
func TestChartScope(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is required for chart acceptance")
	}
	data, err := os.ReadFile("../../examples/registry.json")
	if err != nil {
		t.Fatal(err)
	}
	var registry map[string]any
	if json.Unmarshal(data, &registry) != nil {
		t.Fatal("invalid fixture")
	}
	for _, tc := range []struct {
		name   string
		values map[string]any
		apis   []string
	}{
		{"empty", map[string]any{}, nil},
		{"mixed", map[string]any{"registry": registry}, nil},
		{"monitoring", map[string]any{"monitoring": map[string]any{"serviceMonitor": map[string]any{"enabled": true}, "prometheusRule": map[string]any{"enabled": true}}}, []string{"--api-versions", "monitoring.coreos.com/v1/ServiceMonitor", "--api-versions", "monitoring.coreos.com/v1/PrometheusRule"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objects, err := render(t, tc.values, tc.apis...)
			if err != nil {
				t.Fatal("chart rendering failed")
			}
			identities := map[string]bool{}
			for _, object := range objects {
				kind := object["kind"].(string)
				metadata := object["metadata"].(map[string]any)
				key := kind + "/" + stringValue(metadata["namespace"]) + "/" + metadata["name"].(string)
				if identities[key] {
					t.Fatal("duplicate rendered resource")
				}
				identities[key] = true
				if kind == "Secret" || kind == "CustomResourceDefinition" {
					t.Fatal("chart owns credentials or CRDs")
				}
				if kind == "Lease" || kind == "ConfigMap" && strings.HasSuffix(metadata["name"].(string), "-status") {
					if object["data"] != nil || object["spec"] != nil {
						t.Fatal("Helm resets runtime state")
					}
					if metadata["annotations"].(map[string]any)["helm.sh/resource-policy"] != "keep" {
						t.Fatal("runtime state deleted on uninstall")
					}
				}
				if kind == "Role" || kind == "ClusterRole" {
					for _, raw := range object["rules"].([]any) {
						rule := raw.(map[string]any)
						resources := rule["resources"].([]any)
						verbs := rule["verbs"].([]any)
						if len(rule["resourceNames"].([]any)) == 0 {
							t.Fatal("unnamed management grant")
						}
						for _, resource := range resources {
							for _, verb := range verbs {
								if resource == "*" || verb == "*" || verb == "create" || verb == "delete" || verb == "list" || verb == "watch" {
									t.Fatal("broad management grant")
								}
								if resource == "deployments" && verb == "patch" {
									t.Fatal("unscoped deployment writes")
								}
							}
						}
					}
				}
			}
		})
	}
}
func stringValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
func TestActivationGuards(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is required")
	}
	for _, values := range []map[string]any{{"replicaCount": 1}, {"replicaCount": 2}, {"monitoring": map[string]any{"serviceMonitor": map[string]any{"enabled": true}}}} {
		if _, err := render(t, values); err == nil {
			t.Fatal("unsafe activation accepted")
		}
	}
}

func TestHAConsumerSchemaRequiresExplicitEnrollment(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is required")
	}
	data, err := os.ReadFile("../../examples/registry.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"valid", "missing-lease", "legacy-profile", "three", "null"} {
		t.Run(mode, func(t *testing.T) {
			var registry map[string]any
			if err := json.Unmarshal(data, &registry); err != nil {
				t.Fatal(err)
			}
			cluster := registry["clusters"].([]any)[0].(map[string]any)
			consumer := cluster["consumers"].([]any)[0].(map[string]any)
			deployment := consumer["caDeployment"].(map[string]any)
			consumer["permissionProfile"] = "ca-read-events-lease"
			consumer["leaderElectionLease"] = map[string]any{"namespace": cluster["identityNamespace"], "name": "ca-leader", "uid": "00000000-0000-4000-8000-000000000001"}
			deployment["maxReplicas"] = 2
			switch mode {
			case "missing-lease":
				delete(consumer, "leaderElectionLease")
			case "legacy-profile":
				consumer["permissionProfile"] = "ca-read-events"
			case "three":
				deployment["maxReplicas"] = 3
			case "null":
				deployment["maxReplicas"] = nil
			}
			_, err := render(t, map[string]any{"registry": registry})
			if (err == nil) != (mode == "valid") {
				t.Fatal("HA schema trust boundary incorrect")
			}
		})
	}
}

func TestIssuerRenewalChartScope(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is required")
	}
	data, err := os.ReadFile("../../examples/registry.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"enabled", "legacy", "long-lived", "null", "oauth"} {
		t.Run(mode, func(t *testing.T) {
			var registry map[string]any
			_ = json.Unmarshal(data, &registry)
			clusters := registry["clusters"].([]any)
			c := clusters[0].(map[string]any)
			p := c["provider"].(map[string]any)
			if mode != "legacy" {
				p["longLived"] = false
				delete(p, "rotationPeriodSeconds")
				p["renewal"] = c["lifetime"]
			}
			switch mode {
			case "long-lived":
				p["longLived"] = true
				p["rotationPeriodSeconds"] = 2592000
			case "null":
				p["renewal"] = nil
			case "oauth":
				clusters[1].(map[string]any)["provider"].(map[string]any)["renewal"] = c["lifetime"]
			}
			objects, err := render(t, map[string]any{"registry": registry})
			valid := mode == "enabled" || mode == "legacy"
			if (err == nil) != valid {
				t.Fatal("renewal schema boundary incorrect")
			}
			if !valid {
				return
			}
			ref := p["secret"].(map[string]any)
			sources := 0
			for _, o := range objects {
				if o["kind"] != "Role" {
					continue
				}
				name := o["metadata"].(map[string]any)["name"].(string)
				if !strings.HasSuffix(name, "-src") {
					continue
				}
				for _, raw := range o["rules"].([]any) {
					r := raw.(map[string]any)
					verbs := r["verbs"].([]any)
					names := r["resourceNames"].([]any)
					expectedPatch := mode == "enabled" && names[0] == ref["name"] && o["metadata"].(map[string]any)["namespace"] == ref["namespace"]
					hasPatch := false
					for _, v := range verbs {
						if v == "patch" {
							hasPatch = true
						}
						if v != "get" && v != "patch" {
							t.Fatal("broad source grant")
						}
					}
					if hasPatch != expectedPatch || len(names) != 1 {
						t.Fatal("source PATCH escaped explicit renewal")
					}
					if hasPatch {
						sources++
					}
				}
			}
			if (sources == 1) != (mode == "enabled") {
				t.Fatal("incorrect number of writable sources")
			}
		})
	}
}
