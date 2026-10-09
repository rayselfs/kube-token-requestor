package capacity

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/rayselfs/kube-token-requestor/internal/config"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func preflight(t *testing.T, count int) {
	t.Helper()
	if runtime.GOOS != "linux" || os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Fatal("capacity API test is restricted to fresh Linux GitHub Actions runners")
	}
	if host := os.Getenv("DOCKER_HOST"); host != "" && host != "unix:///var/run/docker.sock" {
		t.Fatal("capacity refuses remote Docker")
	}
	if selected := os.Getenv("DOCKER_CONTEXT"); selected != "" && selected != "default" {
		t.Fatal("capacity refuses a nonlocal Docker context")
	}
	out, err := exec.Command("docker", "context", "inspect", "default", "--format", "{{.Endpoints.docker.Host}}").Output()
	if err != nil || strings.TrimSpace(string(out)) != "unix:///var/run/docker.sock" {
		t.Fatal("capacity Docker endpoint not local")
	}
	out, err = exec.Command("docker", "info", "--format", "{{.MemTotal}}").Output()
	memory, parseErr := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
	minimum := uint64(6 << 30)
	if count == 20 {
		minimum = 14 << 30
	}
	if err != nil || parseErr != nil || memory < minimum {
		t.Fatal("capacity runner memory below the reviewed profile budget")
	}
}
func TestRealChildCapacity(t *testing.T) {
	if os.Getenv("REQUESTOR_CAPACITY_API") != "1" {
		t.Skip("requires explicit owned-runner capacity opt-in")
	}
	count, err := strconv.Atoi(os.Getenv("REQUESTOR_CAPACITY_CHILDREN"))
	if err != nil || (count != 2 && count != 20) {
		t.Fatal("capacity count must be smoke=2 or acceptance=20")
	}
	preflight(t, count)
	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Minute)
	defer cancel()
	f := fresh(t, ctx)
	f.startDatastore(t, ctx)
	a, err := newAuthority()
	if err != nil {
		t.Fatal("capacity CA generation failed")
	}
	children := []*child{}
	tokens := [][]byte{}
	clusters := []config.Cluster{}
	seen := map[string]bool{}
	for i := 0; i < count; i++ {
		child := f.newChild(t, ctx, fmt.Sprintf("child-%02d", i), a)
		cluster, token := child.enroll(t, ctx, a.public)
		if seen[cluster.KubeSystemUID] {
			t.Fatal("capacity API identities are not independent")
		}
		seen[cluster.KubeSystemUID] = true
		children = append(children, child)
		clusters = append(clusters, cluster)
		tokens = append(tokens, token)
	}
	registry := f.installController(t, ctx, clusters, tokens, a.public)
	if seen[registry.ManagementUID] {
		t.Fatal("capacity child must be separate from management")
	}
	f.waitOutputs(t, ctx, registry)
	f.activateCAs(t, ctx, registry)
	f.observeCapacity(t, ctx, registry, children)
	f.outage(t, ctx, registry, children)
	f.guardNodes(t, ctx)
	f.guardNamespace(t, ctx)
	// Only public synthetic status, never URLs, JWTs, private PKI or kubeconfigs.
	manifestPath, path := os.Getenv("REQUESTOR_CAPACITY_MANIFEST"), os.Getenv("REQUESTOR_CAPACITY_EVIDENCE")
	expected := filepath.Join(os.Getenv("RUNNER_TEMP"), "capacity", "evidence.json")
	if os.Getenv("RUNNER_TEMP") == "" || path != expected || !filepath.IsAbs(path) {
		t.Fatal("capacity evidence path not task-local")
	}
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal("verified capacity manifest missing")
	}
	var manifest struct {
		ControllerVersion string `json:"controllerVersion"`
		SourceCommit      string `json:"sourceCommit"`
	}
	if json.Unmarshal(data, &manifest) != nil || len(manifest.SourceCommit) != 40 {
		t.Fatal("capacity source identity missing")
	}
	result := map[string]any{"controllerVersion": manifest.ControllerVersion, "sourceCommit": manifest.SourceCommit, "harnessCommit": os.Getenv("GITHUB_SHA"), "architecture": runtime.GOARCH, "kubernetes": "1.35.8", "clusterAutoscaler": "1.35.2", "provider": "SecretIssuer", "reloadPolicy": "TokenFile", "independentChildAPIs": count, "actualUnchangedCAPods": count * 3, "everyConsumerRotatedTwice": true, "fiveMinuteActualAPIOutage": true, "healthyChildrenRemainedServiceable": true, "failedChildRecoveredWithinSafetyBudget": true, "fourControllerWorkers": true, "scope": "synthetic independent API stores/signers; empty CAPI fleet", "acceleratedLifetimeSeconds": 1200, "naturalLifetimeAcceptance": false, "capacity20Acceptance": count == 20}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil || os.WriteFile(path, append(encoded, '\n'), 0600) != nil {
		t.Fatal("sanitized capacity evidence export failed")
	}
}
