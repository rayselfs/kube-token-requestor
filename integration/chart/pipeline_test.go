package chart

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/observe"
	"github.com/rayselfs/kube-token-requestor/internal/status"
)

// Actual exporter -> scrape -> rendered PromQL -> Alertmanager -> receiver.
// This complements all-rule decision tests; installation on-call approval is separate.
func TestLiveSafetyAlertPipeline(t *testing.T) {
	binaries := map[string]string{}
	for name, version := range map[string]string{"prometheus": "version 3.15.0", "alertmanager": "version 0.34.1"} {
		path, err := exec.LookPath(name)
		if err != nil {
			t.Skip("pinned Prometheus and Alertmanager required for live pipeline")
		}
		out, err := exec.Command(path, "--version").CombinedOutput()
		if err != nil || !strings.Contains(string(out), version) {
			t.Fatal("unexpected monitoring binary version")
		}
		binaries[name] = path
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	type alert struct {
		Status      string            `json:"status"`
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
	}
	type notification struct {
		Receiver string  `json:"receiver"`
		Alerts   []alert `json:"alerts"`
	}
	deliveries := make(chan notification, 64)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var n notification
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "" || json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&n) != nil {
			http.Error(w, "invalid synthetic delivery", 400)
			return
		}
		select {
		case deliveries <- n:
			w.WriteHeader(200)
		default:
			http.Error(w, "bounded receiver full", 503)
		}
	}))
	defer receiver.Close()
	metrics := &observe.Metrics{}
	metrics.Leader.Store(true)
	metrics.Valid.Store(true)
	metrics.Targets.Store(1)
	metrics.Record("child", "ca", "Healthy", time.Now().Add(24*time.Hour))
	metrics.State("child", "ca", status.Consumer{Condition: "Healthy"})
	exporter := httptest.NewServer(metrics.Handler())
	defer exporter.Close()
	metricURL, _ := url.Parse(exporter.URL)
	dir := t.TempDir()
	allocate := func() string {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal("monitoring loopback port allocation failed")
		}
		address := l.Addr().String()
		l.Close()
		return address
	}
	amAddress, promAddress := allocate(), allocate()
	amConfig := filepath.Join(dir, "alertmanager.json")
	writeJSON(t, amConfig, map[string]any{
		"route":     map[string]any{"receiver": "synthetic-owner", "group_by": []string{"alertname"}, "group_wait": "0s", "group_interval": "1s", "repeat_interval": "1h"},
		"receivers": []any{map[string]any{"name": "synthetic-owner", "webhook_configs": []any{map[string]any{"url": receiver.URL, "send_resolved": true}}}},
	})
	objects, err := render(t, map[string]any{"monitoring": map[string]any{"prometheusRule": map[string]any{"enabled": true}}}, "--api-versions", "monitoring.coreos.com/v1/PrometheusRule")
	if err != nil {
		t.Fatal("live alert rule render failed")
	}
	rules := []any{}
	summaries := map[string]string{}
	for _, object := range objects {
		if object["kind"] != "PrometheusRule" {
			continue
		}
		for _, raw := range object["spec"].(map[string]any)["groups"].([]any)[0].(map[string]any)["rules"].([]any) {
			rule := raw.(map[string]any)
			name := rule["alert"].(string)
			if name != "ConsumerSafetyStop" && name != "StopUnconfirmed" {
				continue
			}
			if _, ok := rule["for"]; ok {
				t.Fatal("live safety rule now requires a reviewed hold interval")
			}
			rules = append(rules, rule)
			summaries[name] = rule["annotations"].(map[string]any)["summary"].(string)
		}
	}
	if len(rules) != 2 {
		t.Fatal("live safety rule selection changed")
	}
	rulePath := filepath.Join(dir, "rules.json")
	writeJSON(t, rulePath, map[string]any{"groups": []any{map[string]any{"name": "live-safety", "rules": rules}}})
	promConfig := filepath.Join(dir, "prometheus.json")
	writeJSON(t, promConfig, map[string]any{
		"global":         map[string]any{"scrape_interval": "1s", "evaluation_interval": "1s"},
		"rule_files":     []string{rulePath},
		"alerting":       map[string]any{"alertmanagers": []any{map[string]any{"static_configs": []any{map[string]any{"targets": []string{amAddress}}}}}},
		"scrape_configs": []any{map[string]any{"job_name": "test", "static_configs": []any{map[string]any{"targets": []string{metricURL.Host}, "labels": map[string]string{"namespace": "requestor-test"}}}}},
	})
	start := func(name string, args ...string) {
		command := exec.CommandContext(ctx, binaries[name], args...)
		command.Stdout, command.Stderr = io.Discard, io.Discard
		if command.Start() != nil {
			t.Fatal("isolated monitoring process failed to start")
		}
		t.Cleanup(func() { cancel(); _ = command.Wait() })
	}
	start("alertmanager", "--config.file="+amConfig, "--storage.path="+filepath.Join(dir, "am"), "--web.listen-address="+amAddress, "--cluster.listen-address=", "--log.level=error")
	start("prometheus", "--config.file="+promConfig, "--storage.tsdb.path="+filepath.Join(dir, "prom"), "--web.listen-address="+promAddress, "--log.level=error")
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	for _, address := range []string{amAddress, promAddress} {
		for {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/-/ready", nil)
			res, err := client.Do(req)
			ready := err == nil && res.StatusCode == 200
			if res != nil {
				res.Body.Close()
			}
			if ready {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("monitoring readiness failed")
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	await := func(name, want string) {
		for {
			select {
			case <-ctx.Done():
				t.Fatalf("live pipeline did not deliver %s %s", name, want)
			case n := <-deliveries:
				if n.Receiver != "synthetic-owner" {
					t.Fatal("unexpected live alert receiver")
				}
				for _, a := range n.Alerts {
					summary, ok := summaries[a.Labels["alertname"]]
					if !ok || len(a.Labels) != 8 || a.Labels["severity"] != "critical" || (a.Labels["alertname"] == "ConsumerSafetyStop" && a.Labels["condition"] != "SafetyStopped") || (a.Labels["alertname"] == "StopUnconfirmed" && a.Labels["condition"] != "StopUnconfirmed") || a.Labels["cluster"] != "child" || a.Labels["consumer"] != "ca" || a.Labels["job"] != "test" || a.Labels["namespace"] != "requestor-test" || a.Labels["instance"] != metricURL.Host || len(a.Annotations) != 1 || a.Annotations["summary"] != summary {
						t.Fatal("live alert payload differs from sanitized contract")
					}
					if a.Labels["alertname"] == name && a.Status == want {
						return
					}
				}
			}
		}
	}
	for condition, name := range map[string]string{"SafetyStopped": "ConsumerSafetyStop", "StopUnconfirmed": "StopUnconfirmed"} {
		metrics.State("child", "ca", status.Consumer{Condition: condition})
		await(name, "firing")
		metrics.State("child", "ca", status.Consumer{Condition: "Healthy"})
		await(name, "resolved")
	}
	t.Log("actual controller exporter scraped by Prometheus; unchanged safety rules delivered firing/resolved through Alertmanager; no installation on-call claim")
}
