package chart

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Complements promtool rule evaluation with actual upstream notification delivery.
// A loopback receiver is not an installation owner's on-call acceptance.
func TestAlertmanagerReceiver(t *testing.T) {
	binary, err := exec.LookPath("alertmanager")
	if err != nil {
		t.Skip("pinned Alertmanager required for receiver acceptance")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	version, err := exec.CommandContext(ctx, binary, "--version").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "version 0.34.1") {
		t.Fatal("unexpected Alertmanager version")
	}
	type alert struct {
		Status      string            `json:"status,omitempty"`
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
		StartsAt    time.Time         `json:"startsAt"`
		EndsAt      time.Time         `json:"endsAt"`
	}
	type notification struct {
		Receiver string  `json:"receiver"`
		Alerts   []alert `json:"alerts"`
	}
	deliveries := make(chan notification, 64)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var n notification
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "" || json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&n) != nil {
			http.Error(w, "invalid synthetic notification", http.StatusBadRequest)
			return
		}
		select {
		case deliveries <- n:
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "bounded receiver full", http.StatusServiceUnavailable)
		}
	}))
	defer receiver.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("loopback port allocation failed")
	}
	address := listener.Addr().String()
	listener.Close()
	dir := t.TempDir()
	configuration := "route:\n  receiver: synthetic-owner\n  group_by: [alertname]\n  group_wait: 0s\n  group_interval: 1s\n  repeat_interval: 1h\nreceivers:\n  - name: synthetic-owner\n    webhook_configs:\n      - url: " + receiver.URL + "\n        send_resolved: true\n"
	path := filepath.Join(dir, "alertmanager.yml")
	if os.WriteFile(path, []byte(configuration), 0600) != nil {
		t.Fatal("synthetic receiver config failed")
	}
	command := exec.CommandContext(ctx, binary, "--config.file="+path, "--storage.path="+filepath.Join(dir, "data"), "--web.listen-address="+address, "--cluster.listen-address=", "--log.level=error")
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if command.Start() != nil {
		t.Fatal("isolated Alertmanager start failed")
	}
	defer func() { cancel(); _ = command.Wait() }()
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	base := "http://" + address
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/-/ready", nil)
		res, err := client.Do(req)
		ready := err == nil && res.StatusCode == http.StatusOK
		if res != nil {
			res.Body.Close()
		}
		if ready {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("Alertmanager readiness failed")
		case <-time.After(100 * time.Millisecond):
		}
	}
	objects, err := render(t, map[string]any{"monitoring": map[string]any{"prometheusRule": map[string]any{"enabled": true}}}, "--api-versions", "monitoring.coreos.com/v1/PrometheusRule")
	if err != nil {
		t.Fatal("receiver rule rendering failed")
	}
	expected := map[string]alert{}
	start := time.Now().UTC().Add(-time.Minute)
	for _, object := range objects {
		if object["kind"] != "PrometheusRule" {
			continue
		}
		for _, raw := range object["spec"].(map[string]any)["groups"].([]any)[0].(map[string]any)["rules"].([]any) {
			rule := raw.(map[string]any)
			name := rule["alert"].(string)
			expected[name] = alert{Labels: map[string]string{"alertname": name, "severity": rule["labels"].(map[string]any)["severity"].(string)}, Annotations: map[string]string{"summary": rule["annotations"].(map[string]any)["summary"].(string)}, StartsAt: start, EndsAt: time.Now().UTC().Add(10 * time.Minute)}
		}
	}
	if len(expected) != 11 {
		t.Fatal("new or missing alert requires receiver review")
	}
	submit := func(resolved bool) {
		batch := []alert{}
		for _, item := range expected {
			if resolved {
				item.EndsAt = time.Now().UTC().Add(-time.Second)
			}
			batch = append(batch, item)
		}
		data, _ := json.Marshal(batch)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/v2/alerts", bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/json")
		res, err := client.Do(req)
		if err != nil {
			t.Fatal("synthetic alert submission failed")
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatal("synthetic alert rejected")
		}
	}
	await := func(status string) {
		seen := map[string]bool{}
		for len(seen) < len(expected) {
			select {
			case <-ctx.Done():
				t.Fatalf("receiver did not deliver every %s notification", status)
			case n := <-deliveries:
				if n.Receiver != "synthetic-owner" {
					t.Fatal("unexpected receiver route")
				}
				for _, item := range n.Alerts {
					want, ok := expected[item.Labels["alertname"]]
					if !ok || len(item.Labels) != 2 || len(item.Annotations) != 1 || item.Labels["severity"] != want.Labels["severity"] || item.Annotations["summary"] != want.Annotations["summary"] {
						t.Fatal("receiver payload differs from sanitized rule contract")
					}
					if item.Status == status {
						seen[item.Labels["alertname"]] = true
					}
				}
			}
		}
	}
	submit(false)
	await("firing")
	submit(true)
	await("resolved")
	t.Log("all eleven alerts delivered firing and resolved through upstream Alertmanager to an isolated receiver; operator on-call acceptance remains separate")
}
