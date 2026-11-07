package chart

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitOpsChartHasNoWorkloadAuthority(t *testing.T) {
	data, err := os.ReadFile("../../examples/gitops-registry.json")
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
					t.Fatal("GitOps granted workload authority")
				}
			}
		}
	}
	monitored, err := render(t, map[string]any{"registry": registry, "monitoring": map[string]any{"prometheusRule": map[string]any{"enabled": true}}}, "--api-versions", "monitoring.coreos.com/v1/PrometheusRule")
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(monitored)
	if !strings.Contains(string(encoded), "GitOpsCredentialBlocked") {
		t.Fatal("missing blocked-credential alert")
	}

	c := registry["clusters"].([]any)[0].(map[string]any)["consumers"].([]any)[0].(map[string]any)
	c["reloadPolicy"] = "StopStart"
	if _, err := render(t, map[string]any{"registry": registry}); err == nil {
		t.Fatal("CA lifecycle accepted for GitOps")
	}
}

// Evaluate the actual rendered expression through firing and recovery.
func TestGitOpsAlertRecovery(t *testing.T) {
	if _, err := exec.LookPath("promtool"); err != nil {
		t.Skip("promtool required")
	}
	data, err := os.ReadFile("../../examples/gitops-registry.json")
	if err != nil {
		t.Fatal(err)
	}
	var registry map[string]any
	if err := json.Unmarshal(data, &registry); err != nil {
		t.Fatal(err)
	}
	objects, err := render(t, map[string]any{"registry": registry, "monitoring": map[string]any{"prometheusRule": map[string]any{"enabled": true}}}, "--api-versions", "monitoring.coreos.com/v1/PrometheusRule")
	if err != nil {
		t.Fatal(err)
	}
	for _, obj := range objects {
		if obj["kind"] != "PrometheusRule" {
			continue
		}
		for _, group := range obj["spec"].(map[string]any)["groups"].([]any) {
			for _, raw := range group.(map[string]any)["rules"].([]any) {
				rule := raw.(map[string]any)
				if rule["alert"] != "GitOpsCredentialBlocked" {
					continue
				}
				dir := t.TempDir()
				rules := filepath.Join(dir, "rules.json")
				writeJSON(t, rules, map[string]any{"groups": []any{map[string]any{"name": "gitops", "rules": []any{rule}}}})
				labels := map[string]string{"job": "test", "namespace": "requestor-test", "cluster": "child", "consumer": "gitops", "condition": "GitOpsBlocked", "severity": "critical"}
				fixture := map[string]any{"rule_files": []string{rules}, "evaluation_interval": "1m", "tests": []any{map[string]any{
					"interval": "1m", "input_series": []any{map[string]any{"series": `kube_token_requestor_condition{job="test",namespace="requestor-test",cluster="child",consumer="gitops",condition="GitOpsBlocked"}`, "values": "1x5 0x5"}},
					"alert_rule_test": []any{map[string]any{"eval_time": "4m", "alertname": "GitOpsCredentialBlocked", "exp_alerts": []any{map[string]any{"exp_labels": labels, "exp_annotations": rule["annotations"]}}}, map[string]any{"eval_time": "8m", "alertname": "GitOpsCredentialBlocked", "exp_alerts": []any{}}},
				}}}
				file := filepath.Join(dir, "test.json")
				writeJSON(t, file, fixture)
				if out, err := exec.Command("promtool", "test", "rules", file).CombinedOutput(); err != nil {
					t.Fatalf("firing/recovery: %s", out)
				}
				return
			}
		}
	}
	t.Fatal("missing GitOps rule")
}
