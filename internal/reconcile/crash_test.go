package reconcile

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/status"
	apps "k8s.io/api/apps/v1"
	autoscaling "k8s.io/api/autoscaling/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	kt "k8s.io/client-go/testing"
)

// Decision tests: the fake API models failure before a mutation and loss of its
// response after commitment. It does not emulate Kubernetes RBAC or deployment draining.
func TestFreshProcessCompletesDurableStopAfterInterruption(t *testing.T) {
	for _, boundary := range []string{"before-scale", "committed-scale-response-lost"} {
		t.Run(boundary, func(t *testing.T) {
			ctx := context.Background()
			digest := "sha256:" + strings.Repeat("1", 64)
			one := int32(1)
			consumer := config.Consumer{ID: "affected", CADeployment: config.Deployment{Namespace: "ns", Name: "ca", UID: "deployment-uid", ImageDigest: digest}}
			d := &apps.Deployment{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "ca", UID: "deployment-uid", ResourceVersion: "1", Generation: 1}, Spec: apps.DeploymentSpec{Replicas: &one, Template: core.PodTemplateSpec{Spec: core.PodSpec{Containers: []core.Container{{Image: "test@" + digest}}}}}, Status: apps.DeploymentStatus{ObservedGeneration: 1, Replicas: 1, ReadyReplicas: 1}}
			client := fake.NewClientset(&core.ConfigMap{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "status", UID: "status-uid"}}, d)
			store := &status.Store{Client: client, Namespace: "ns", Name: "status", UID: "status-uid"}
			initial := &Engine{Management: client, Store: store}
			sibling := status.Consumer{Condition: "Healthy", Expiry: time.Unix(2000003600, 0), LastSuccess: time.Unix(2000000000, 0)}
			if err := initial.save(ctx, "sibling", &sibling); err != nil {
				t.Fatal(err)
			}
			persisted, err := store.Read(ctx)
			if err != nil {
				t.Fatal(err)
			}
			wantSibling := persisted.Consumers["sibling"]
			interrupted, patches := false, 0
			client.PrependReactor("get", "deployments", func(a kt.Action) (bool, runtime.Object, error) {
				if a.GetSubresource() == "scale" {
					current, err := client.Tracker().Get(schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}, "ns", "ca")
					if err != nil {
						return true, nil, err
					}
					object := current.(*apps.Deployment)
					return true, &autoscaling.Scale{ObjectMeta: object.ObjectMeta, Spec: autoscaling.ScaleSpec{Replicas: *object.Spec.Replicas}}, nil
				}
				if boundary == "before-scale" && !interrupted {
					interrupted = true
					return true, nil, provider.Transport
				}
				return false, nil, nil
			})
			client.PrependReactor("patch", "deployments", func(a kt.Action) (bool, runtime.Object, error) {
				if a.GetSubresource() != "scale" {
					t.Fatal("unexpected workload mutation")
				}
				patches++
				// Verify the durable latch before the first simulated scale can commit.
				// Reactors hold the fake client lock; read the tracker rather than
				// recursively invoking the client while verifying committed state.
				record, err := client.Tracker().Get(schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}, "ns", "status")
				var state status.Snapshot
				if err != nil || json.Unmarshal([]byte(record.(*core.ConfigMap).Data["state.json"]), &state) != nil || !state.Consumers[consumer.ID].StopLatched {
					t.Fatal("scale preceded durable stop intent")
				}
				current, err := client.Tracker().Get(schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}, "ns", "ca")
				if err != nil {
					return true, nil, err
				}
				object := current.(*apps.Deployment).DeepCopy()
				zero := int32(0)
				object.Spec.Replicas, object.Status.Replicas, object.Status.ReadyReplicas = &zero, 0, 0
				if err := client.Tracker().Update(schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}, object, "ns"); err != nil {
					return true, nil, err
				}
				if boundary == "committed-scale-response-lost" && !interrupted {
					interrupted = true
					return true, nil, provider.Transport
				}
				// The generated Deployment fake decodes Patch as Deployment even for
				// the scale subresource; the separate REST test covers actual Scale JSON.
				return true, object, nil
			})
			entry := status.Consumer{}
			if err := initial.stop(ctx, consumer, &entry, "SafetyStopped"); err != provider.Transport || !interrupted {
				t.Fatal("fault boundary was not exercised", err)
			}
			state, err := store.Read(ctx)
			if err != nil || !state.Consumers[consumer.ID].StopLatched {
				t.Fatal("interruption lost durable latch")
			}
			// No previous Engine state survives; recovery uses only the persisted record.
			freshStore := &status.Store{Client: client, Namespace: "ns", Name: "status", UID: "status-uid"}
			recovered := state.Consumers[consumer.ID]
			fresh := &Engine{Management: client, Store: freshStore}
			if err := fresh.stop(ctx, consumer, &recovered, "SafetyStopped"); err != nil {
				t.Fatal("fresh process could not finish owned stop", err)
			}
			if patches != 1 {
				t.Fatal("stop duplicated a committed scale operation", patches)
			}
			actual, err := client.AppsV1().Deployments("ns").Get(ctx, "ca", meta.GetOptions{})
			if err != nil || *actual.Spec.Replicas != 0 {
				t.Fatal("recovery resumed or failed to stop CA")
			}
			after, err := freshStore.Read(ctx)
			if err != nil || !after.Consumers[consumer.ID].StopLatched || after.Consumers[consumer.ID].Intent != nil || !reflect.DeepEqual(after.Consumers["sibling"], wantSibling) {
				t.Fatal("recovery changed sibling state or cleared stop authority")
			}
		})
	}
}
