package chart

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAlertRules(t *testing.T) {
	if _, err := exec.LookPath("promtool"); err != nil {
		t.Skip("promtool is required for monitoring acceptance")
	}
	objects, err := render(t, map[string]any{"monitoring": map[string]any{"prometheusRule": map[string]any{"enabled": true}}}, "--api-versions", "monitoring.coreos.com/v1/PrometheusRule")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, obj := range objects {
		if obj["kind"] != "PrometheusRule" {
			continue
		}
		raw, _ := json.Marshal(obj["spec"])
		rulePath := filepath.Join(dir, "rules.json")
		if err := os.WriteFile(rulePath, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("promtool", "check", "rules", rulePath).CombinedOutput(); err != nil {
			t.Fatalf("invalid rules: %s", out)
		}
		rules := obj["spec"].(map[string]any)["groups"].([]any)[0].(map[string]any)["rules"].([]any)
		for _, test := range []struct {
			name, series, values string
			labels               map[string]string
			summary              string
		}{
			{"ConsumerSafetyStop", `kube_token_requestor_condition{job="test",namespace="requestor-test",cluster="child",consumer="ca",condition="SafetyStopped"}`, "1x10", map[string]string{"job": "test", "namespace": "requestor-test", "cluster": "child", "consumer": "ca", "condition": "SafetyStopped", "severity": "critical"}, "Validate replacement, acknowledge only this stop, then explicitly resume the CA."},
			{"StopUnconfirmed", `kube_token_requestor_condition{job="test",namespace="requestor-test",cluster="child",consumer="ca",condition="StopUnconfirmed"}`, "1x10", map[string]string{"job": "test", "namespace": "requestor-test", "cluster": "child", "consumer": "ca", "condition": "StopUnconfirmed", "severity": "critical"}, "Urgently check the named CA; preserve all workers."},
		} {
			t.Run(test.name, func(t *testing.T) {
				var selected any
				for _, r := range rules {
					if r.(map[string]any)["alert"] == test.name {
						selected = r
					}
				}
				if selected == nil {
					t.Fatal("missing critical alert")
				}
				b, _ := json.Marshal(map[string]any{"groups": []any{map[string]any{"name": "test", "rules": []any{selected}}}})
				p := filepath.Join(dir, test.name+"-rules.json")
				if err := os.WriteFile(p, b, 0600); err != nil {
					t.Fatal(err)
				}
				fixture := map[string]any{"rule_files": []string{p}, "evaluation_interval": "1m", "tests": []any{map[string]any{"interval": "1m", "input_series": []any{map[string]any{"series": test.series, "values": test.values}}, "alert_rule_test": []any{map[string]any{"eval_time": "5m", "alertname": test.name, "exp_alerts": []any{map[string]any{"exp_labels": test.labels, "exp_annotations": map[string]string{"summary": test.summary}}}}}}}}
				b, _ = json.Marshal(fixture)
				p = filepath.Join(dir, test.name+"-tests.json")
				if err := os.WriteFile(p, b, 0600); err != nil {
					t.Fatal(err)
				}
				if out, err := exec.Command("promtool", "test", "rules", p).CombinedOutput(); err != nil {
					t.Fatalf("alert did not reach firing state: %s", out)
				}
			})
		}
		// Explicitly stopped installations must not page because they have no leader.
		for _, r := range rules {
			if r.(map[string]any)["alert"] == "RequestorUnavailable" && !strings.Contains(r.(map[string]any)["expr"].(string), "vector(0 > bool 0)") {
				t.Fatal("stopped installation pages unavailable")
			}
		}
	}
}
