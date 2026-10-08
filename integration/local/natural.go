package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/publish"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func naturalPolicy(duration time.Duration, l config.Lifetime) bool {
	return duration >= 48*time.Hour && duration <= 49*time.Hour &&
		l.RequestedSeconds == 86400 && l.AcceptedMinSeconds >= 79200 && l.AcceptedMaxSeconds <= 90000 &&
		l.RenewBeforeSeconds >= 3600 && l.RenewBeforeSeconds <= 43200 &&
		l.StopBeforeSeconds >= 1800 && l.ClockSkewSeconds <= 60
}

// This evidence is synthetic natural-policy observation, never operator adoption approval.
func observeNatural(root, path, manifestPath, evidencePath string, duration time.Duration) (result error) {
	valuesData, err := os.ReadFile(path)
	if err != nil {
		return provider.Trust
	}
	var values struct {
		Registry config.Registry `json:"registry"`
	}
	if json.Unmarshal(valuesData, &values) != nil || values.Registry.Validate() != nil || len(values.Registry.Clusters) != 2 {
		return provider.Trust
	}
	for _, cluster := range values.Registry.Clusters {
		if cluster.Provider.Type != "SecretIssuer" || !naturalPolicy(duration, cluster.Lifetime) {
			return provider.Trust
		}
		for _, consumer := range cluster.Consumers {
			if consumer.ReloadPolicy != "TokenFile" {
				return provider.Trust
			}
		}
	}
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil || len(manifestData) > 1<<20 {
		return provider.Trust
	}
	var manifest struct {
		ControllerVersion string `json:"controllerVersion"`
		SourceCommit      string `json:"sourceCommit"`
		Image             struct {
			Reference   string `json:"reference"`
			IndexDigest string `json:"indexDigest"`
		} `json:"image"`
	}
	if json.Unmarshal(manifestData, &manifest) != nil || len(manifest.SourceCommit) != 40 || !strings.HasPrefix(manifest.ControllerVersion, "v") || manifest.Image.Reference != "ghcr.io/rayselfs/kube-token-requestor" || len(manifest.Image.IndexDigest) != 71 || !strings.HasPrefix(manifest.Image.IndexDigest, "sha256:") {
		return provider.Trust
	}
	// Evidence stays with the protected task-local kubeconfigs, never in a source checkout.
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return provider.Trust
	}
	absoluteEvidence, err := filepath.Abs(evidencePath)
	if err != nil || filepath.Dir(absoluteEvidence) != filepath.Dir(absoluteRoot) || filepath.Base(absoluteEvidence) != "natural-evidence.json" {
		return provider.Trust
	}
	management, _, err := local(root, "management")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	expectedImage := manifest.Image.Reference + "@" + manifest.Image.IndexDigest
	check := func(call context.Context) error {
		d, err := management.AppsV1().Deployments("requestor-test").Get(call, "requestor-kube-token-requestor", meta.GetOptions{})
		if err != nil || d.Spec.Replicas == nil || *d.Spec.Replicas != 2 || d.Status.ReadyReplicas != 2 || len(d.Spec.Template.Spec.Containers) != 1 || d.Spec.Template.Spec.Containers[0].Image != expectedImage {
			return provider.Trust
		}
		cm, err := management.CoreV1().ConfigMaps("requestor-test").Get(call, "requestor-kube-token-requestor-registry", meta.GetOptions{})
		if err != nil {
			return provider.Trust
		}
		registry, err := config.Parse(bytes.NewBufferString(cm.Data["registry.json"]))
		if err != nil {
			return provider.Trust
		}
		actual, _ := json.Marshal(registry)
		expected, _ := json.Marshal(values.Registry)
		if !bytes.Equal(actual, expected) {
			return provider.Conflict
		}
		return nil
	}
	if err := check(ctx); err != nil {
		return err
	}
	firstCluster := values.Registry.Clusters[0]
	firstConsumer := firstCluster.Consumers[0]
	first, err := publish.Read(ctx, management, firstConsumer)
	if err != nil {
		return err
	}
	claims, err := credential.Parse(string(first.Data["token"]))
	if err != nil || claims.Lifetime(time.Now(), time.Minute, firstCluster.Lifetime.AcceptedMinSeconds, firstCluster.Lifetime.AcceptedMaxSeconds) != nil || publish.StoredExpiry(first, firstCluster, firstConsumer).Before(time.Now().Add(22*time.Hour)) {
		return provider.Trust
	}
	started := time.Now().UTC()
	lastObserved := started
	record := map[string]any{"controllerVersion": manifest.ControllerVersion, "sourceCommit": manifest.SourceCommit, "image": expectedImage, "startedAt": started, "scope": "synthetic loopback kind; no operator adoption", "status": "running", "naturalRotations": 0, "oldTokenRejected": false}
	write := func() error {
		data, err := json.MarshalIndent(record, "", "  ")
		if err != nil {
			return provider.Trust
		}
		temp, err := os.CreateTemp(filepath.Dir(absoluteEvidence), ".natural-evidence-*")
		if err != nil {
			return provider.Trust
		}
		name := temp.Name()
		defer os.Remove(name)
		if _, err := temp.Write(data); err != nil {
			temp.Close()
			return provider.Trust
		}
		if err := temp.Close(); err != nil {
			return provider.Trust
		}
		if os.Rename(name, absoluteEvidence) != nil {
			return provider.Trust
		}
		return nil
	}
	if err := write(); err != nil {
		return err
	}
	defer func() {
		record["finishedAt"] = time.Now().UTC()
		record["observationHours"] = time.Since(started).Hours()
		record["status"] = "failed"
		if result == nil && time.Since(started) >= 48*time.Hour {
			record["status"] = "passed"
		} else if result == nil {
			result = provider.Trust
		}
		if err := write(); err != nil {
			result = err
		}
	}()
	return observeProgress(root, path, duration, func(rotations int, rejected bool, podUID string) error {
		if time.Since(lastObserved) > 90*time.Second {
			return provider.Transport
		}
		lastObserved = time.Now()
		call, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		if err := check(call); err != nil {
			return err
		}
		record["lastObservedAt"] = time.Now().UTC()
		record["observationHours"] = time.Since(started).Hours()
		record["naturalRotations"] = rotations
		record["oldTokenRejected"] = rejected
		record["sameCAPodUID"] = podUID
		return write()
	})
}
