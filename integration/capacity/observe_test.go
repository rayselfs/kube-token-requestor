package capacity

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/issue"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/publish"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type sample struct {
	hashes map[string]string
	pods   map[string]types.UID
}

func (f *fixture) sample(t *testing.T, ctx context.Context, registry config.Registry, children []*child, validate bool) *sample {
	t.Helper()
	result := &sample{hashes: map[string]string{}, pods: map[string]types.UID{}}
	unique := map[string]bool{}
	for i, c := range registry.Clusters {
		outside := c
		outside.Endpoint = children[i].bootstrap.Host
		for _, consumer := range c.Consumers {
			output, err := publish.Read(ctx, f.client, consumer)
			if err != nil || len(output.Data["token"]) == 0 || publish.StoredExpiry(output, c, consumer).Before(time.Now().Add(time.Minute)) {
				t.Fatal("capacity output missing or unsafe")
			}
			hash := credential.Hash(output.Data["token"])
			if unique[hash] {
				t.Fatal("capacity reused an independent consumer credential")
			}
			unique[hash] = true
			result.hashes[consumer.ID] = hash
			if validate {
				client, err := issue.Client(outside.Endpoint, provider.IssuerCredential{Bearer: string(output.Data["token"]), CA: output.Data["ca.crt"]})
				if err != nil || issue.ValidateConsumer(ctx, client, outside, consumer) != nil {
					t.Fatal("actual capacity consumer identity/rights failed")
				}
			}
			pods, err := f.client.CoreV1().Pods(f.namespace).List(ctx, meta.ListOptions{LabelSelector: "capacity-ca=" + consumer.ID})
			if err != nil || len(pods.Items) != 1 || len(pods.Items[0].Status.ContainerStatuses) != 1 {
				t.Fatal("capacity CA Pod identity missing")
			}
			pod := pods.Items[0]
			state := pod.Status.ContainerStatuses[0]
			if !state.Ready || state.RestartCount != 0 {
				t.Fatal("capacity CA restarted or lost readiness")
			}
			result.pods[consumer.ID] = pod.UID
			if validate {
				lines := int64(30)
				logs, err := f.client.CoreV1().Pods(f.namespace).GetLogs(pod.Name, &core.PodLogOptions{TailLines: &lines}).DoRaw(ctx)
				if err != nil || strings.Contains(string(logs), "Unauthorized") || strings.Contains(string(logs), "forbidden") {
					t.Fatal("capacity CA API scans failed")
				}
			}
		}
	}
	return result
}
func (f *fixture) waitOutputs(t *testing.T, ctx context.Context, registry config.Registry) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Minute)
	defer deadline.Stop()
	for {
		ready := 0
		for _, c := range registry.Clusters {
			for _, v := range c.Consumers {
				s, err := publish.Read(ctx, f.client, v)
				if err == nil && publish.StoredExpiry(s, c, v).After(time.Now().Add(15*time.Minute)) {
					ready++
				}
			}
		}
		if ready == len(registry.Clusters)*3 {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("capacity issuance cancelled")
		case <-deadline.C:
			t.Fatal("all independent capacity outputs did not become valid")
		case <-time.After(time.Second):
		}
	}
}
func (f *fixture) observeCapacity(t *testing.T, ctx context.Context, registry config.Registry, children []*child) {
	t.Helper()
	first := f.sample(t, ctx, registry, children, true)
	previous := first
	rotations := map[string]int{}
	finish := time.Now().Add(5 * time.Minute)
	for time.Now().Before(finish) {
		select {
		case <-ctx.Done():
			t.Fatal("capacity rotation cancelled")
		case <-time.After(20 * time.Second):
		}
		current := f.sample(t, ctx, registry, children, false)
		for id, hash := range current.hashes {
			if current.pods[id] != first.pods[id] {
				t.Fatal("capacity Pod replaced during token rotation")
			}
			if hash != previous.hashes[id] {
				rotations[id]++
			}
		}
		previous = current
	}
	for id := range first.hashes {
		if rotations[id] < 2 {
			t.Fatal("capacity target did not rotate twice within budget")
		}
	}
	f.sample(t, ctx, registry, children, true)
	t.Logf("actual capacity baseline passed: %d distinct API identities, %d actual unchanged CA Pods, every consumer rotated at least twice", len(children), len(first.hashes))
}
func (f *fixture) outage(t *testing.T, ctx context.Context, registry config.Registry, children []*child) {
	t.Helper()
	failed := children[0]
	before := f.sample(t, ctx, registry, children, false)
	pod, err := f.client.CoreV1().Pods(f.namespace).Get(ctx, failed.name, meta.GetOptions{})
	if err != nil || pod.Labels["capacity-component"] != failed.name || len(pod.Spec.Containers) != 1 || pod.Spec.Containers[0].Image != apiImage {
		t.Fatal("capacity outage target not owned")
	}
	f.guardNamespace(t, ctx)
	uid, zero := pod.UID, int64(0)
	if f.client.CoreV1().Pods(f.namespace).Delete(ctx, pod.Name, meta.DeleteOptions{GracePeriodSeconds: &zero, Preconditions: &meta.Preconditions{UID: &uid}}) != nil {
		t.Fatal("guarded capacity outage deletion failed")
	}
	stoppedAt := time.Now()
	// New work must stop; allow the bounded in-flight remote acquisition to drain first.
	select {
	case <-ctx.Done():
		t.Fatal("capacity outage drain cancelled")
	case <-time.After(75 * time.Second):
	}
	paused := f.sample(t, ctx, registry, children, false)
	until := stoppedAt.Add(5 * time.Minute)
	for time.Now().Before(until) {
		select {
		case <-ctx.Done():
			t.Fatal("capacity outage cancelled")
		case <-time.After(20 * time.Second):
		}
		current := f.sample(t, ctx, registry, children, false)
		for _, consumer := range registry.Clusters[0].Consumers {
			if current.hashes[consumer.ID] != paused.hashes[consumer.ID] {
				t.Fatal("unavailable child published after in-flight drain")
			}
		}
		for id, uid := range before.pods {
			if current.pods[id] != uid {
				t.Fatal("capacity CA replaced during outage")
			}
		}
	}
	last := f.sample(t, ctx, registry, children, false)
	for _, c := range registry.Clusters[1:] {
		for _, v := range c.Consumers {
			if last.hashes[v.ID] == paused.hashes[v.ID] {
				t.Fatal("healthy capacity child starved during peer outage")
			}
		}
	}
	f.startAPI(t, ctx, failed.name, failed.endpoint)
	port := f.forward(t, ctx, failed.name)
	failed.bootstrap.Host = fmt.Sprintf("https://127.0.0.1:%d", port)
	recovery := time.NewTimer(3 * time.Minute)
	defer recovery.Stop()
	for {
		all := true
		for _, v := range registry.Clusters[0].Consumers {
			s, err := publish.Read(ctx, f.client, v)
			if err != nil || credential.Hash(s.Data["token"]) == paused.hashes[v.ID] {
				all = false
			}
		}
		if all {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("capacity recovery cancelled")
		case <-recovery.C:
			t.Fatal("failed child did not recover within safety budget")
		case <-time.After(time.Second):
		}
	}
	for _, c := range registry.Clusters {
		for _, v := range c.Consumers {
			d, err := f.client.AppsV1().Deployments(f.namespace).Get(ctx, v.CADeployment.Name, meta.GetOptions{})
			if err != nil || string(d.UID) != v.CADeployment.UID || d.Spec.Replicas == nil || *d.Spec.Replicas != 1 {
				t.Fatal("capacity CA safety deadline was exceeded")
			}
		}
	}
	final := f.sample(t, ctx, registry, children, true)
	for id, uid := range before.pods {
		if final.pods[id] != uid {
			t.Fatal("capacity recovery replaced a CA")
		}
	}
	t.Logf("actual capacity outage passed: full five-minute API loss, %d healthy children remained serviceable, failed child recovered without CA replacement", len(children)-1)
}
