package chart

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestAccessChartHasNoWorkloadAuthority(t *testing.T) {
	data, err := os.ReadFile("../../examples/access-registry.json")
	if err != nil {
		t.Fatal(err)
	}
	var registry map[string]any
	if json.Unmarshal(data, &registry) != nil {
		t.Fatal("fixture")
	}
	objects, err := render(t, map[string]any{"registry": registry})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range objects {
		if o["kind"] != "Role" && o["kind"] != "ClusterRole" {
			continue
		}
		for _, v := range o["rules"].([]any) {
			rule := v.(map[string]any)
			for _, r := range rule["resources"].([]any) {
				if strings.Contains(r.(string), "deployment") {
					t.Fatal("Access granted workload authority")
				}
			}
		}
	}
	monitored, err := render(t, map[string]any{"registry": registry, "monitoring": map[string]any{"prometheusRule": map[string]any{"enabled": true}}}, "--api-versions", "monitoring.coreos.com/v1/PrometheusRule")
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(monitored)
	if !strings.Contains(string(encoded), "AccessCredentialBlocked") {
		t.Fatal("missing blocked-credential alert")
	}

	c := registry["clusters"].([]any)[0].(map[string]any)["consumers"].([]any)[0].(map[string]any)
	c["reloadPolicy"] = "StopStart"
	if _, err := render(t, map[string]any{"registry": registry}); err == nil {
		t.Fatal("CA lifecycle accepted for Access")
	}
}
