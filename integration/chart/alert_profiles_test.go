package chart

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the actual rendered PromQL, including recovery, rather than checking expression text.
func TestActiveAlertProfiles(t *testing.T) {
	if _, err := exec.LookPath("promtool"); err != nil {
		t.Skip("promtool is required for monitoring acceptance")
	}
	objects, err := render(t, map[string]any{
		"replicaCount": 2, "image": map[string]any{"digest": "sha256:" + strings.Repeat("1", 64)},
		"registry":      map[string]any{"managementUID": "00000000-0000-0000-0000-000000000001"},
		"networkPolicy": map[string]any{"enabled": false},
		"monitoring":    map[string]any{"prometheusRule": map[string]any{"enabled": true}},
	}, "--api-versions", "monitoring.coreos.com/v1/PrometheusRule")
	if err != nil {
		t.Fatal("active monitoring rendering failed")
	}
	rules := map[string]map[string]any{}
	for _, obj := range objects {
		if obj["kind"] == "PrometheusRule" {
			for _, raw := range obj["spec"].(map[string]any)["groups"].([]any)[0].(map[string]any)["rules"].([]any) {
				r := raw.(map[string]any)
				rules[r["alert"].(string)] = r
			}
		}
	}
	target := map[string]string{"job": "test", "namespace": "requestor-test", "cluster": "child", "consumer": "ca"}
	labels := func(extra map[string]string, severity string) map[string]string {
		m := map[string]string{"severity": severity}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	series := func(metric string, extra string) string {
		return metric + `{job="test",namespace="requestor-test"` + extra + `}`
	}
	cases := []struct {
		name, metric, values, severity string
		extra                          map[string]string
	}{
		{"RequestorUnavailable", series("kube_token_requestor_leader", ""), "0x15 1x15", "critical", nil},
		{"MultipleLeaders", series("kube_token_requestor_leader", ""), "2x15 1x15", "critical", nil},
		{"ConfigRejected", series("kube_token_requestor_config_valid", ""), "0x15 1x15", "warning", nil},
		{"ConsumerRenewalFailed", series("kube_token_requestor_condition", `,cluster="child",consumer="ca",condition="Transport"`), "1x15 0x15", "warning", map[string]string{"job": "test", "namespace": "requestor-test", "cluster": "child", "consumer": "ca", "condition": "Transport"}},
		{"ConsumerExpiryWarning", series("kube_token_requestor_token_expiry_timestamp_seconds", `,cluster="child",consumer="ca"`), "600x15 100000x15", "critical", target},
		{"BootstrapRequired", series("kube_token_requestor_condition", `,cluster="child",consumer="ca",condition="BootstrapRequired"`), "1x15 0x15", "critical", map[string]string{"job": "test", "namespace": "requestor-test", "cluster": "child", "consumer": "ca", "condition": "BootstrapRequired"}},
		{"IssuerRotationDue", series("kube_token_requestor_issuer_rotation_due_timestamp_seconds", `,cluster="child"`), "600x15 1000000x15", "warning", map[string]string{"job": "test", "namespace": "requestor-test", "cluster": "child"}},
		{"ConsumerSafetyStop", series("kube_token_requestor_condition", `,cluster="child",consumer="ca",condition="SafetyStopped"`), "1x15 0x15", "critical", map[string]string{"job": "test", "namespace": "requestor-test", "cluster": "child", "consumer": "ca", "condition": "SafetyStopped"}},
		{"StopUnconfirmed", series("kube_token_requestor_condition", `,cluster="child",consumer="ca",condition="StopUnconfirmed"`), "1x15 0x15", "critical", map[string]string{"job": "test", "namespace": "requestor-test", "cluster": "child", "consumer": "ca", "condition": "StopUnconfirmed"}},
		{"OAuthDependencyFailure", series("kube_token_requestor_exchange_total", `,cluster="child",result="Transport"`), "0+1x15 15x15", "warning", map[string]string{"job": "test", "namespace": "requestor-test", "cluster": "child", "result": "Transport"}},
		{"StaleOrMissingTarget", series("kube_token_requestor_registry_targets", ""), "2x15 0x15", "critical", nil},
		{"StaleOrMissingTarget", series("kube_token_requestor_last_observed_timestamp_seconds", `,cluster="child",consumer="ca"`), "0x15 1200+60x15", "critical", target},
	}
	if len(rules) != 11 {
		t.Fatal("new or missing alert requires a reviewed profile")
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := rules[tc.name]
			if rule == nil {
				t.Fatal("required alert missing")
			}
			dir := t.TempDir()
			ruleFile := filepath.Join(dir, "rules.json")
			writeJSON(t, ruleFile, map[string]any{"groups": []any{map[string]any{"name": "test", "rules": []any{rule}}}})
			alerts := []any{map[string]any{"exp_labels": labels(tc.extra, tc.severity), "exp_annotations": rule["annotations"]}}
			fixture := map[string]any{"rule_files": []string{ruleFile}, "evaluation_interval": "1m", "tests": []any{map[string]any{"interval": "1m", "input_series": []any{map[string]any{"series": tc.metric, "values": tc.values}}, "alert_rule_test": []any{
				map[string]any{"eval_time": "14m", "alertname": tc.name, "exp_alerts": alerts},
				map[string]any{"eval_time": "25m", "alertname": tc.name, "exp_alerts": []any{}},
			}}}}
			path := filepath.Join(dir, "profiles.json")
			writeJSON(t, path, fixture)
			if out, err := exec.Command("promtool", "test", "rules", path).CombinedOutput(); err != nil {
				t.Fatalf("alert firing/recovery failed: %s", out)
			}
		})
	}
}
func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil || os.WriteFile(path, data, 0600) != nil {
		t.Fatal("monitoring fixture write failed")
	}
}
