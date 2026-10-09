package capacity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/issue"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/publish"
	"github.com/rayselfs/kube-token-requestor/internal/status"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// This is a separate fault profile; unlike capacity, one CA is expected to stop.
func TestActualConsumerFailureIsolation(t *testing.T) {
	if os.Getenv("REQUESTOR_CAPACITY_CONSUMER_FAILURE") != "1" {
		t.Skip("requires explicit fresh-runner consumer-failure opt-in")
	}
	preflight(t, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	f := fresh(t, ctx)
	f.startDatastore(t, ctx)
	a, err := newAuthority()
	if err != nil {
		t.Fatal("consumer-failure public authority creation failed")
	}
	children := []*child{}
	clusters := []config.Cluster{}
	tokens := [][]byte{}
	for i := 0; i < 2; i++ {
		child := f.newChild(t, ctx, fmt.Sprintf("child-%02d", i), a)
		cluster, token := child.enroll(t, ctx, a.public)
		children = append(children, child)
		clusters = append(clusters, cluster)
		tokens = append(tokens, token)
	}
	registry := f.installController(t, ctx, clusters, tokens, a.public)
	f.waitOutputs(t, ctx, registry)
	f.activateCAs(t, ctx, registry)
	before := f.sample(t, ctx, registry, children, true)
	affected := registry.Clusters[0].Consumers[0]
	name := "capacity-kube-token-requestor"
	sum := sha256.Sum256([]byte(affected.ID))
	roleName := name + "-" + hex.EncodeToString(sum[:])[:8] + "-ca"
	role, err := f.client.RbacV1().Roles(f.namespace).Get(ctx, roleName, meta.GetOptions{})
	if err != nil || len(role.Rules) != 2 || !reflect.DeepEqual(role.Rules[1].APIGroups, []string{"apps"}) || len(role.Rules[1].Resources) != 1 || role.Rules[1].Resources[0] != "deployments/scale" || !reflect.DeepEqual(role.Rules[1].Verbs, []string{"patch"}) || !reflect.DeepEqual(role.Rules[1].ResourceNames, []string{affected.CADeployment.Name}) {
		t.Fatal("generated affected-CA grant differs from reviewed fault scope")
	}
	original := role.DeepCopy()
	role.Rules = role.Rules[:1]
	f.guardNamespace(t, ctx)
	if _, err := f.client.RbacV1().Roles(f.namespace).Update(ctx, role, meta.UpdateOptions{}); err != nil {
		t.Fatal("fixture-only named scale denial failed")
	}
	restored := false
	restore := func(call context.Context) {
		f.guardNamespace(t, call)
		current, err := f.client.RbacV1().Roles(f.namespace).Get(call, roleName, meta.GetOptions{})
		if err != nil || current.UID != original.UID || !reflect.DeepEqual(current.Rules, original.Rules[:1]) {
			t.Fatal("affected role changed; restoration rejected")
		}
		current.Rules = original.Rules
		if _, err := f.client.RbacV1().Roles(f.namespace).Update(call, current, meta.UpdateOptions{}); err != nil {
			t.Fatal("fixture role restoration failed")
		}
		restored = true
	}
	t.Cleanup(func() {
		if !restored {
			cleanup, done := context.WithTimeout(context.Background(), time.Minute)
			defer done()
			restore(cleanup)
		}
	})
	output, err := publish.Read(ctx, f.client, affected)
	if err != nil {
		t.Fatal("affected output binding changed")
	}
	// Only an owned synthetic output is made unusable; no real token is logged or stored in files.
	output.Data["token"] = []byte("synthetic-unusable")
	if _, err := f.client.CoreV1().Secrets(f.namespace).Update(ctx, output, meta.UpdateOptions{}); err != nil {
		t.Fatal("owned synthetic output fault failed")
	}
	statusObject, err := f.client.CoreV1().ConfigMaps(f.namespace).Get(ctx, name+"-status", meta.GetOptions{})
	if err != nil {
		t.Fatal("consumer-failure durable state missing")
	}
	store := &status.Store{Client: f.client, Namespace: f.namespace, Name: statusObject.Name, UID: string(statusObject.UID)}
	deadline := time.Now().Add(2 * time.Minute)
	for {
		state, err := store.Read(ctx)
		if err == nil && state.Consumers[affected.ID].StopLatched && state.Consumers[affected.ID].Condition == "StopUnconfirmed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("actual denied stop was not durably reported")
		}
		select {
		case <-ctx.Done():
			t.Fatal("consumer-failure cancelled")
		case <-time.After(time.Second):
		}
	}
	// Measure only renewals after the denial is durable, not pre-fault rotations.
	baseline := map[string]string{}
	for _, cluster := range registry.Clusters {
		for _, consumer := range cluster.Consumers {
			if consumer.ID == affected.ID {
				continue
			}
			output, err := publish.Read(ctx, f.client, consumer)
			if err != nil {
				t.Fatal("healthy post-denial baseline unavailable")
			}
			baseline[consumer.ID] = credential.Hash(output.Data["token"])
		}
	}
	// A stopped/blocked consumer must not starve its sibling or the other child.
	finish := time.Now().Add(3 * time.Minute)
	rotated := map[string]bool{}
	faultStarted := time.Now()
	for {
		for _, cluster := range registry.Clusters {
			for _, consumer := range cluster.Consumers {
				if consumer.ID == affected.ID {
					continue
				}
				output, err := publish.Read(ctx, f.client, consumer)
				if err != nil || publish.StoredExpiry(output, cluster, consumer).Before(time.Now().Add(time.Minute)) {
					t.Fatal("healthy fault-profile output became unsafe")
				}
				if credential.Hash(output.Data["token"]) != baseline[consumer.ID] {
					rotated[consumer.ID] = true
				}
				pods, err := f.client.CoreV1().Pods(f.namespace).List(ctx, meta.ListOptions{LabelSelector: "capacity-ca=" + consumer.ID})
				if err != nil || len(pods.Items) != 1 || pods.Items[0].UID != before.pods[consumer.ID] || len(pods.Items[0].Status.ContainerStatuses) != 1 || !pods.Items[0].Status.ContainerStatuses[0].Ready || pods.Items[0].Status.ContainerStatuses[0].RestartCount != 0 {
					t.Fatal("healthy CA replaced or stopped by peer failure")
				}
			}
		}
		if len(rotated) == 5 && time.Since(faultStarted) >= 90*time.Second {
			break
		}
		if time.Now().After(finish) {
			t.Fatal("unsafe consumer starved actual healthy output renewal")
		}
		select {
		case <-ctx.Done():
			t.Fatal("consumer-failure cancelled")
		case <-time.After(10 * time.Second):
		}
	}
	stateDuringFault, err := store.Read(ctx)
	if err != nil || !stateDuringFault.Consumers[affected.ID].StopLatched || stateDuringFault.Consumers[affected.ID].Condition != "StopUnconfirmed" {
		t.Fatal("denied stop state did not persist throughout healthy renewal")
	}
	deniedSeconds := int(time.Since(faultStarted).Seconds())
	restore(ctx)
	deadline = time.Now().Add(3 * time.Minute)
	for {
		d, err := f.client.AppsV1().Deployments(f.namespace).Get(ctx, affected.CADeployment.Name, meta.GetOptions{})
		output, outputErr := publish.Read(ctx, f.client, affected)
		pods, podsErr := f.client.CoreV1().Pods(f.namespace).List(ctx, meta.ListOptions{LabelSelector: "capacity-ca=" + affected.ID})
		if err == nil && string(d.UID) == affected.CADeployment.UID && d.Spec.Replicas != nil && *d.Spec.Replicas == 0 && podsErr == nil && len(pods.Items) == 0 && outputErr == nil && publish.StoredExpiry(output, registry.Clusters[0], affected).After(time.Now().Add(15*time.Minute)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("affected CA did not remain stopped with a healthy replacement after grant recovery")
		}
		select {
		case <-ctx.Done():
			t.Fatal("consumer recovery cancelled")
		case <-time.After(time.Second):
		}
	}
	state, err := store.Read(ctx)
	if err != nil || !state.Consumers[affected.ID].StopLatched {
		t.Fatal("recovery cleared operator-controlled safety latch")
	}
	output, err = publish.Read(ctx, f.client, affected)
	if err != nil {
		t.Fatal("recovered output binding changed")
	}
	outside := registry.Clusters[0]
	outside.Endpoint = children[0].bootstrap.Host
	client, clientErr := issue.Client(outside.Endpoint, provider.IssuerCredential{Bearer: string(output.Data["token"]), CA: output.Data["ca.crt"]})
	if err != nil || clientErr != nil || issue.ValidateConsumer(ctx, client, outside, affected) != nil {
		t.Fatal("recovered replacement identity/rights invalid")
	}
	for _, cluster := range registry.Clusters {
		for _, consumer := range cluster.Consumers {
			d, err := f.client.AppsV1().Deployments(f.namespace).Get(ctx, consumer.CADeployment.Name, meta.GetOptions{})
			expected := int32(1)
			if consumer.ID == affected.ID {
				expected = 0
			}
			if err != nil || string(d.UID) != consumer.CADeployment.UID || d.Spec.Replicas == nil || *d.Spec.Replicas != expected {
				t.Fatal("consumer deployment identity or recovery replicas changed")
			}
			if consumer.ID == affected.ID {
				continue
			}
			pods, err := f.client.CoreV1().Pods(f.namespace).List(ctx, meta.ListOptions{LabelSelector: "capacity-ca=" + consumer.ID})
			if err != nil || len(pods.Items) != 1 || pods.Items[0].UID != before.pods[consumer.ID] || len(pods.Items[0].Status.ContainerStatuses) != 1 || !pods.Items[0].Status.ContainerStatuses[0].Ready || pods.Items[0].Status.ContainerStatuses[0].RestartCount != 0 {
				t.Fatal("healthy CA changed during affected consumer recovery")
			}
		}
	}
	f.guardNamespace(t, ctx)
	f.guardNodes(t, ctx)
	manifestBytes, err := os.ReadFile(os.Getenv("REQUESTOR_CAPACITY_MANIFEST"))
	var manifest struct {
		ControllerVersion string `json:"controllerVersion"`
		SourceCommit      string `json:"sourceCommit"`
	}
	if err != nil || json.Unmarshal(manifestBytes, &manifest) != nil || len(manifest.SourceCommit) != 40 {
		t.Fatal("consumer-failure release identity missing")
	}
	path := os.Getenv("REQUESTOR_CAPACITY_EVIDENCE")
	if path != filepath.Join(os.Getenv("RUNNER_TEMP"), "capacity", "evidence.json") || !filepath.IsAbs(path) {
		t.Fatal("consumer-failure evidence path not task-local")
	}
	result := map[string]any{"controllerVersion": manifest.ControllerVersion, "sourceCommit": manifest.SourceCommit, "harnessCommit": os.Getenv("GITHUB_SHA"), "architecture": runtime.GOARCH, "kubernetes": "1.35.8", "clusterAutoscaler": "1.35.2", "acceleratedLifetimeSeconds": 1200, "deniedStopObservationSeconds": deniedSeconds, "provider": "SecretIssuer", "reloadPolicy": "TokenFile", "independentChildAPIs": 2, "actualInitialCAPods": 6, "actualDeniedEmergencyStop": true, "fiveHealthyOutputsRenewedDuringPeerFailure": true, "fiveUnchangedReadyCAPods": true, "affectedCAStoppedAfterGrantRecovery": true, "affectedHealthyReplacementIdentityRights": true, "safetyLatchRetainedNoAutomaticResume": true, "scope": "fresh synthetic APIs and empty read-only CAPI fleet", "naturalLifetimeAcceptance": false}
	data, _ := json.MarshalIndent(result, "", "  ")
	if os.WriteFile(path, append(data, '\n'), 0600) != nil {
		t.Fatal("sanitized consumer-failure receipt export failed")
	}
	t.Log("actual consumer failure passed: denied stop stayed latched, five healthy consumers renewed, affected CA stopped after grant recovery without automatic resume")
}
