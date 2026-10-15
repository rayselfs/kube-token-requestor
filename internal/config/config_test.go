package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func fixture(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile("../../examples/registry.json")
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if json.Unmarshal(data, &value) != nil {
		t.Fatal("invalid fixture")
	}
	return value
}
func cluster(value map[string]any, index int) map[string]any {
	return value["clusters"].([]any)[index].(map[string]any)
}
func consumer(value map[string]any, index int) map[string]any {
	return cluster(value, 0)["consumers"].([]any)[index].(map[string]any)
}
func provider(value map[string]any, index int) map[string]any {
	return cluster(value, index)["provider"].(map[string]any)
}

func TestExample(t *testing.T) {
	data, _ := json.Marshal(fixture(t))
	result, err := Parse(bytes.NewReader(data))
	if err != nil || len(result.Clusters) != 2 || len(result.Clusters[0].Consumers) != 2 {
		t.Fatalf("example rejected: %v", err)
	}
}

func TestInvalidRegistries(t *testing.T) {
	cases := map[string]func(map[string]any){
		"output mount namespace mismatch": func(v map[string]any) { consumer(v, 0)["secret"].(map[string]any)["namespace"] = "other" },
		"reserved OAuth volume":           func(v map[string]any) { provider(v, 1)["subjectTokenVolume"] = "management-api" },
		"null cross-provider field":       func(v map[string]any) { provider(v, 0)["tokenEndpoint"] = nil },
		"OAuth reuses issuer Secret":      func(v map[string]any) { provider(v, 1)["clientSecret"] = provider(v, 0)["secret"] },
		"issuer reuses OAuth Secret": func(v map[string]any) {
			provider(v, 0)["secret"] = provider(v, 1)["clientSecret"]
			items := v["clusters"].([]any)
			items[0], items[1] = items[1], items[0]
		},
		"null scalar": func(v map[string]any) { cluster(v, 0)["identityNamespace"] = nil },
		"shared issuer": func(v map[string]any) {
			cluster(v, 1)["provider"] = provider(v, 0)
			cluster(v, 1)["expectedIssuer"] = cluster(v, 0)["expectedIssuer"]
		},
		"unsupported schema":       func(v map[string]any) { v["schemaVersion"] = 2 },
		"unknown field":            func(v map[string]any) { v["credential"] = "sensitive-canary" },
		"missing explicit enabled": func(v map[string]any) { delete(cluster(v, 0), "enabled") },
		"null explicit enabled":    func(v map[string]any) { cluster(v, 0)["enabled"] = nil },
		"wrong key case":           func(v map[string]any) { v["SchemaVersion"] = v["schemaVersion"]; delete(v, "schemaVersion") },
		"invalid UUID":             func(v map[string]any) { v["managementUID"] = "sensitive-canary" },
		"duplicate cluster UID":    func(v map[string]any) { cluster(v, 1)["kubeSystemUID"] = cluster(v, 0)["kubeSystemUID"] },
		"duplicate endpoint":       func(v map[string]any) { cluster(v, 1)["endpoint"] = cluster(v, 0)["endpoint"] },
		"HTTP":                     func(v map[string]any) { cluster(v, 0)["endpoint"] = "http://workload-a.example.invalid:6443" },
		"credentials in URL": func(v map[string]any) {
			cluster(v, 0)["endpoint"] = "https://user:sensitive-canary@workload-a.example.invalid:6443"
		},
		"query":                            func(v map[string]any) { cluster(v, 0)["endpoint"] = "https://workload-a.example.invalid:6443?" },
		"fragment":                         func(v map[string]any) { cluster(v, 0)["endpoint"] = "https://workload-a.example.invalid:6443#" },
		"API path":                         func(v map[string]any) { cluster(v, 0)["endpoint"] = "https://workload-a.example.invalid:6443/api" },
		"zero port":                        func(v map[string]any) { cluster(v, 0)["endpoint"] = "https://workload-a.example.invalid:0" },
		"implicit API port":                func(v map[string]any) { cluster(v, 0)["endpoint"] = "https://workload-a.example.invalid" },
		"invalid host":                     func(v map[string]any) { cluster(v, 0)["endpoint"] = "https://bad..example.invalid:6443" },
		"timing":                           func(v map[string]any) { cluster(v, 0)["lifetime"].(map[string]any)["stopBeforeSeconds"] = 86400 },
		"duplicate output":                 func(v map[string]any) { consumer(v, 1)["secret"] = consumer(v, 0)["secret"] },
		"source output collision":          func(v map[string]any) { consumer(v, 0)["secret"] = provider(v, 0)["secret"] },
		"duplicate CA deployment":          func(v map[string]any) { consumer(v, 1)["caDeployment"] = consumer(v, 0)["caDeployment"] },
		"issuer equals consumer":           func(v map[string]any) { consumer(v, 0)["serviceAccount"] = provider(v, 0)["serviceAccount"] },
		"consumer enabled with parent off": func(v map[string]any) { consumer(v, 0)["enabled"] = true },
		"unknown reload":                   func(v map[string]any) { consumer(v, 0)["reloadPolicy"] = "fallback" },
		"unknown permission profile":       func(v map[string]any) { consumer(v, 0)["permissionProfile"] = "admin" },
		"cross provider field":             func(v map[string]any) { provider(v, 0)["tokenEndpoint"] = "https://identity.example.invalid/token" },
		"missing lifetime policy":          func(v map[string]any) { delete(provider(v, 0), "longLived") },
		"missing rotation":                 func(v map[string]any) { provider(v, 0)["rotationPeriodSeconds"] = 0 },
		"OAuth inline credential":          func(v map[string]any) { provider(v, 1)["client_secret"] = "sensitive-canary" },
		"privileged OAuth group": func(v map[string]any) {
			cluster(v, 1)["expectedIssuer"].(map[string]any)["groups"] = []string{"system:masters"}
		},
		"unexpected issuer group": func(v map[string]any) {
			cluster(v, 0)["expectedIssuer"].(map[string]any)["groups"] = []string{"system:masters"}
		},
		"unknown provider": func(v map[string]any) { provider(v, 1)["type"] = "OIDC" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			v := fixture(t)
			mutate(v)
			data, _ := json.Marshal(v)
			_, err := Parse(bytes.NewReader(data))
			if !errors.Is(err, ErrInvalid) {
				t.Fatal("unsafe config accepted")
			}
			if strings.Contains(err.Error(), "canary") {
				t.Fatal("sensitive error")
			}
		})
	}
}

func TestDuplicateJSONKeys(t *testing.T) {
	for _, value := range []string{`{"schemaVersion":1,"schemaVersion":1}`, `{"schemaVersion":1,"\u0073chemaVersion":1}`, `{"clusters":[{"enabled":true,"enabled":false}]}`} {
		if _, err := Parse(strings.NewReader(value)); err == nil {
			t.Fatal("duplicate key accepted")
		}
	}
}
func TestMalformedAndOversize(t *testing.T) {
	for _, value := range []string{"null", "[]", "{} {}", strings.Repeat(" ", MaxBytes+1), `{"schemaVersion":1.5}`} {
		if _, err := Parse(strings.NewReader(value)); err == nil {
			t.Fatal("malformed input accepted")
		}
	}
	if _, err := Parse(errorReader{}); err == nil {
		t.Fatal("read error accepted")
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestEmptyRoster(t *testing.T) {
	value := fixture(t)
	value["clusters"] = []any{}
	data, _ := json.Marshal(value)
	if _, err := Parse(bytes.NewReader(data)); err != nil {
		t.Fatal("explicit empty roster rejected")
	}
	delete(value, "clusters")
	data, _ = json.Marshal(value)
	if _, err := Parse(bytes.NewReader(data)); err == nil {
		t.Fatal("missing roster accepted")
	}
}
func TestNamedReferences(t *testing.T) {
	value := fixture(t)
	consumer(value, 0)["secret"].(map[string]any)["name"] = "ca.identity.token"
	data, _ := json.Marshal(value)
	if _, err := Parse(bytes.NewReader(data)); err != nil {
		t.Fatal("valid subdomain object name rejected")
	}
}
func FuzzParse(f *testing.F) {
	data, _ := os.ReadFile("../../examples/registry.json")
	f.Add(data)
	renewable, _ := os.ReadFile("../../examples/renewable-registry.json")
	f.Add(renewable)
	f.Add([]byte(`{"x":1,"x":2}`))
	f.Add([]byte("null"))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := Parse(bytes.NewReader(data))
		if err == nil && r.Validate() != nil {
			t.Fatal("parsed invalid registry")
		}
		if err != nil && err != ErrInvalid {
			t.Fatal("unsanitized parser error")
		}
	})
}

func TestHAEnrollmentIsExplicitAndBounded(t *testing.T) {
	for _, mode := range []string{"valid", "candidate", "missing-lease", "legacy-profile", "wrong-namespace", "zero", "three", "null"} {
		t.Run(mode, func(t *testing.T) {
			v := fixture(t)
			item := consumer(v, 0)
			dep := item["caDeployment"].(map[string]any)
			dep["maxReplicas"] = 2
			item["permissionProfile"] = "ca-read-events-lease"
			item["leaderElectionLease"] = map[string]any{"namespace": cluster(v, 0)["identityNamespace"], "name": "ca-leader", "uid": "10000000-0000-4000-8000-000000000099"}
			switch mode {
			case "candidate":
				delete(dep, "maxReplicas")
			case "missing-lease":
				delete(item, "leaderElectionLease")
			case "legacy-profile":
				item["permissionProfile"] = "ca-read-events"
			case "wrong-namespace":
				item["leaderElectionLease"].(map[string]any)["namespace"] = "other"
			case "zero":
				dep["maxReplicas"] = 0
			case "three":
				dep["maxReplicas"] = 3
			case "null":
				dep["maxReplicas"] = nil
			}
			data, _ := json.Marshal(v)
			_, err := Parse(bytes.NewReader(data))
			if (err == nil) != (mode == "valid" || mode == "candidate") {
				t.Fatal("HA declaration boundary incorrect")
			}
		})
	}
}

func TestIssuerRenewalPolicy(t *testing.T) {
	for _, mode := range []string{"valid", "long-lived", "zero-budget", "unknown-field", "oauth", "null"} {
		t.Run(mode, func(t *testing.T) {
			v := fixture(t)
			p := provider(v, 0)
			p["longLived"] = false
			delete(p, "rotationPeriodSeconds")
			policy := cluster(v, 0)["lifetime"].(map[string]any)
			p["renewal"] = policy
			switch mode {
			case "long-lived":
				p["longLived"] = true
				p["rotationPeriodSeconds"] = 2592000
			case "zero-budget":
				policy["renewBeforeSeconds"] = 0
			case "unknown-field":
				policy["credentials"] = "synthetic-canary"
			case "oauth":
				provider(v, 1)["renewal"] = policy
			case "null":
				p["renewal"] = nil
			}
			data, _ := json.Marshal(v)
			_, err := Parse(bytes.NewReader(data))
			if (err == nil) != (mode == "valid") {
				t.Fatal("incorrect renewal policy boundary")
			}
		})
	}
}

func TestRenewableExample(t *testing.T) {
	data, err := os.ReadFile("../../examples/renewable-registry.json")
	if err != nil {
		t.Fatal(err)
	}
	registry, err := Parse(bytes.NewReader(data))
	if err != nil || registry.Clusters[0].Provider.Renewal == nil {
		t.Fatal("renewable example rejected", err)
	}
}
