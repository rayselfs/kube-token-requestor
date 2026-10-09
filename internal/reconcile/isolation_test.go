package reconcile

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/publish"
	"github.com/rayselfs/kube-token-requestor/internal/status"
	"github.com/rayselfs/kube-token-requestor/internal/testutil"
	apps "k8s.io/api/apps/v1"
	autoscaling "k8s.io/api/autoscaling/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	kt "k8s.io/client-go/testing"
)

func TestSafetyPreflightFailureDoesNotStarveSiblingWork(t *testing.T) {
	for _, boundary := range []string{"wrong-deployment-uid", "stop-denied"} {
		t.Run(boundary, func(t *testing.T) {
			now := time.Unix(2000000000, 0)
			ca := []byte("synthetic-public-ca")
			digest := "sha256:" + strings.Repeat("1", 64)
			yes, no := true, false
			one, zero := int32(1), int32(0)
			cluster := config.Cluster{ID: "child", Enabled: &yes, IdentityNamespace: "identity", Audiences: []string{"api"}, CASHA256: credential.Hash(ca), Lifetime: config.Lifetime{StopBeforeSeconds: 60, ClockSkewSeconds: 5}}
			objects := []runtime.Object{&core.ConfigMap{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "status", UID: "status-uid"}}}
			for _, name := range []string{"affected", "sibling"} {
				consumer := config.Consumer{ID: name, Enabled: &no, ServiceAccount: config.ServiceAccount{Name: name, UID: name + "-sa"}, Secret: config.Ref{Namespace: "ns", Name: name, UID: name + "-secret"}, CADeployment: config.Deployment{Namespace: "ns", Name: name, UID: name + "-deployment", ImageDigest: digest}, ReloadPolicy: "TokenFile"}
				cluster.Consumers = append(cluster.Consumers, consumer)
				token, replicas, uid := "synthetic-unusable", &one, consumer.CADeployment.UID
				if name == "sibling" {
					token = testutil.Token("system:serviceaccount:identity:sibling", "identity", "sibling", "sibling-sa", []string{"api"}, now, 3600)
					replicas = &zero
				} else if boundary == "wrong-deployment-uid" {
					uid = "foreign-deployment"
				}
				objects = append(objects,
					&core.Secret{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: name, UID: types.UID(consumer.Secret.UID), Annotations: map[string]string{publish.Owner: name}}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"ca.crt": ca, "token": []byte(token)}},
					&apps.Deployment{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: name, UID: types.UID(uid)}, Spec: apps.DeploymentSpec{Replicas: replicas, Template: core.PodTemplateSpec{Spec: core.PodSpec{Containers: []core.Container{{Image: "synthetic@" + digest}}}}}},
				)
			}
			client := fake.NewClientset(objects...)
			client.PrependReactor("get", "deployments", func(a kt.Action) (bool, runtime.Object, error) {
				if a.GetSubresource() == "scale" {
					return true, &autoscaling.Scale{ObjectMeta: meta.ObjectMeta{UID: "affected-deployment"}, Spec: autoscaling.ScaleSpec{Replicas: 1}}, nil
				}
				return false, nil, nil
			})
			patches := 0
			client.PrependReactor("patch", "deployments", func(a kt.Action) (bool, runtime.Object, error) {
				patches++
				if a.(kt.PatchAction).GetName() != "affected" || a.GetSubresource() != "scale" {
					t.Fatal("affected preflight touched sibling or workload template")
				}
				return true, nil, provider.Auth
			})
			observed := map[string]string{}
			store := &status.Store{Client: client, Namespace: "ns", Name: "status", UID: "status-uid"}
			engine := &Engine{Management: client, Store: store, Now: func() time.Time { return now }, Observe: func(_, consumer, result string, _ time.Time) { observed[consumer] = result }}
			err := engine.Slice(context.Background(), cluster, "generation", 0, false)
			want := provider.Trust
			if boundary == "stop-denied" {
				want = provider.Auth
			}
			if err != want {
				t.Fatal("affected failure was hidden", err)
			}
			if observed["sibling"] != "Healthy" {
				t.Fatal("one unsafe consumer starved sibling work")
			}
			if (boundary == "wrong-deployment-uid" && patches != 0) || (boundary == "stop-denied" && patches != 1) {
				t.Fatal("preflight failure bypassed identity guard or repeated stop in the same slice")
			}
			if boundary == "stop-denied" {
				state, err := store.Read(context.Background())
				if err != nil || !state.Consumers["affected"].StopLatched || state.Consumers["affected"].Condition != "StopUnconfirmed" {
					t.Fatal("denied stop lost durable emergency state")
				}
			}
		})
	}
}
