package controller

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/rayselfs/kube-token-requestor/internal/observe"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/reconcile"
	"github.com/rayselfs/kube-token-requestor/internal/status"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

func TestStartupStatusConflict(t *testing.T) {
	data, err := os.ReadFile("../../examples/registry.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, persistent := range []bool{false, true} {
		t.Run(map[bool]string{false: "transient", true: "bounded"}[persistent], func(t *testing.T) {
			client := fake.NewClientset(
				&core.ConfigMap{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "registry", UID: "registry-uid"}, Data: map[string]string{"registry.json": string(data)}},
				&core.Namespace{ObjectMeta: meta.ObjectMeta{Name: "kube-system", UID: "00000000-0000-0000-0000-000000000001"}},
				&core.ConfigMap{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "status", UID: "status-uid"}, Data: map[string]string{"state.json": `{"schemaVersion":1,"generation":"old","consumers":{"ca-one":{"revision":9,"condition":"SafetyStopped","stopLatched":true}}}`}},
			)
			updates := 0
			client.PrependReactor("update", "configmaps", func(action clienttesting.Action) (bool, apiruntime.Object, error) {
				updates++
				if updates == 1 || persistent {
					return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, "status", errors.New("synthetic overlap"))
				}
				return false, nil, nil
			})
			r := &runtime{client: client, opts: Options{Namespace: "ns", Registry: "registry"}, metrics: &observe.Metrics{}, engine: &reconcile.Engine{Store: &status.Store{Client: client, Namespace: "ns", Name: "status", UID: "status-uid"}}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			err := r.reload(ctx, ctx)
			if persistent {
				if err != provider.Conflict || updates > 5 || updates < 2 || r.registry != nil {
					t.Fatalf("startup retry must remain bounded and fail closed: err=%v updates=%d", err, updates)
				}
				return
			}
			if err != nil || updates != 2 || r.registry == nil || !r.metrics.Valid.Load() {
				t.Fatalf("HA startup conflict not recovered: err=%v updates=%d", err, updates)
			}
			snapshot, readErr := r.engine.Store.Read(ctx)
			if readErr != nil || !snapshot.Consumers["ca-one"].StopLatched || snapshot.Consumers["ca-one"].Revision != 9 {
				t.Fatal("startup retry lost durable safety state")
			}
			if r.cancel != nil {
				r.cancel()
			}
		})
	}
}
