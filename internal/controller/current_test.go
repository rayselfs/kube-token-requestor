package controller

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/reconcile"
	"github.com/rayselfs/kube-token-requestor/internal/status"
	coord "k8s.io/api/coordination/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestLivePublicationPins(t *testing.T) {
	data, err := os.ReadFile("../../examples/registry.json")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := config.Parse(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	normalized, _ := json.Marshal(parsed)
	generation := credential.Hash(normalized)
	for _, tc := range []struct {
		name   string
		change func(*core.ConfigMap, *coord.Lease, *status.Snapshot)
	}{
		{"accepted", func(*core.ConfigMap, *coord.Lease, *status.Snapshot) {}},
		{"registry UID", func(cm *core.ConfigMap, _ *coord.Lease, _ *status.Snapshot) { cm.UID = "new" }},
		{"invalid registry", func(cm *core.ConfigMap, _ *coord.Lease, _ *status.Snapshot) { cm.Data["registry.json"] = "{}" }},
		{"changed registry generation", func(cm *core.ConfigMap, _ *coord.Lease, _ *status.Snapshot) {
			cm.Data["registry.json"] = strings.Replace(string(data), `"requestedSeconds": 86400`, `"requestedSeconds": 86399`, 1)
		}},
		{"lease UID", func(_ *core.ConfigMap, l *coord.Lease, _ *status.Snapshot) { l.UID = "new" }},
		{"other holder", func(_ *core.ConfigMap, l *coord.Lease, _ *status.Snapshot) {
			other := "new-leader"
			l.Spec.HolderIdentity = &other
		}},
		{"accepted status generation", func(_ *core.ConfigMap, _ *coord.Lease, s *status.Snapshot) { s.Generation = "new" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cm := &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "registry", UID: "registry-uid"}, Data: map[string]string{"registry.json": string(data)}}
			holder := "pod-uid"
			lease := &coord.Lease{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "lease", UID: "lease-uid"}, Spec: coord.LeaseSpec{HolderIdentity: &holder}}
			snapshot := status.Snapshot{SchemaVersion: 1, Generation: generation, Consumers: map[string]status.Consumer{}}
			tc.change(cm, lease, &snapshot)
			state, _ := json.Marshal(snapshot)
			client := fake.NewClientset(cm, lease, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "status", UID: "status-uid"}, Data: map[string]string{"state.json": string(state)}})
			r := &runtime{client: client, opts: Options{Namespace: "ns", Registry: "registry", Lease: "lease", Identity: holder}, registryUID: "registry-uid", leaseUID: "lease-uid", engine: &reconcile.Engine{Store: &status.Store{Client: client, Namespace: "ns", Name: "status", UID: "status-uid"}}}
			err := r.current(context.Background(), generation)
			if (err == nil) != (tc.name == "accepted") {
				t.Fatal("live publication guard mismatch", err)
			}
			for _, action := range client.Actions() {
				if action.GetVerb() != "get" {
					t.Fatal("guard mutates API")
				}
			}
		})
	}
}
