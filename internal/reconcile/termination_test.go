package reconcile

import (
	"context"
	"testing"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/publish"
	"github.com/rayselfs/kube-token-requestor/internal/status"
	"github.com/rayselfs/kube-token-requestor/internal/testutil"
	autoscaling "k8s.io/api/autoscaling/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	kt "k8s.io/client-go/testing"
)

func TestStoppedRequiresTerminatingReplicaAccounting(t *testing.T) {
	for _, mode := range []string{"complete", "terminating", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			c, d := haFixture(0)
			switch mode {
			case "terminating":
				*d.Status.TerminatingReplicas = 2
			case "unknown":
				d.Status.TerminatingReplicas = nil
			}
			client := fake.NewClientset(d)
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			err := stopped(ctx, client, c)
			want := map[string]error{"complete": nil, "terminating": provider.Transport, "unknown": provider.Trust}[mode]
			if err != want {
				t.Fatalf("stop barrier: got %v, want %v", err, want)
			}
			for _, action := range client.Actions() {
				if action.GetVerb() != "get" {
					t.Fatal("barrier performed a write")
				}
			}
		})
	}
}

func TestConsumerCannotPublishWithUnknownOrPendingTermination(t *testing.T) {
	for _, mode := range []string{"unknown-active", "unknown-stopped", "terminating-stopped"} {
		t.Run(mode, func(t *testing.T) {
			count := int32(0)
			if mode == "unknown-active" {
				count = 1
			}
			consumer, d := haFixture(count)
			consumer.ReloadPolicy = "StopStart"
			consumer.ServiceAccount = config.ServiceAccount{Name: "ca", UID: "sa-uid"}
			consumer.Secret = config.Ref{Namespace: "ns", Name: "output", UID: "output-uid"}
			want := error(provider.Trust)
			if mode == "terminating-stopped" {
				*d.Status.TerminatingReplicas = 2
				want = provider.Transport
			} else {
				d.Status.TerminatingReplicas = nil
			}
			now := time.Unix(2000000000, 0)
			ca := []byte("public-test-ca")
			cluster := config.Cluster{IdentityNamespace: "identity", CASHA256: credential.Hash(ca), Audiences: []string{"api"}, Lifetime: config.Lifetime{RenewBeforeSeconds: 300, StopBeforeSeconds: 60, ClockSkewSeconds: 5}}
			output := &core.Secret{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "output", UID: "output-uid", Annotations: map[string]string{publish.Owner: "ca"}}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"ca.crt": ca, "token": []byte(testutil.Token("system:serviceaccount:identity:ca", "identity", "ca", "sa-uid", []string{"api"}, now, 3600))}}
			client := fake.NewClientset(d, output)
			engine := &Engine{Management: client, Now: func() time.Time { return now }}
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			if err := engine.consumer(ctx, cluster, consumer, "generation", status.Consumer{}, nil, provider.IssuerCredential{}, provider.Transport, true); err != want {
				t.Fatalf("guard got %v, want %v", err, want)
			}
			for _, action := range client.Actions() {
				if action.GetVerb() != "get" {
					t.Fatal("unsafe preflight wrote to API")
				}
			}
		})
	}
}

func TestUnknownTerminationStillRequestsSafetyStop(t *testing.T) {
	consumer, d := haFixture(2)
	consumer.ReloadPolicy = "StopStart"
	consumer.Secret = config.Ref{Namespace: "ns", Name: "output", UID: "output-uid"}
	d.Status.TerminatingReplicas = nil
	client := fake.NewClientset(d,
		&core.Secret{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "output", UID: "output-uid", Annotations: map[string]string{publish.Owner: consumer.ID}}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"ca.crt": []byte("public-test-ca"), "token": []byte("invalid-synthetic-token")}},
		&core.ConfigMap{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "status", UID: "status-uid"}},
	)
	client.PrependReactor("get", "deployments", func(a kt.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() == "scale" {
			return true, &autoscaling.Scale{ObjectMeta: meta.ObjectMeta{UID: d.UID, ResourceVersion: "1"}, Spec: autoscaling.ScaleSpec{Replicas: *d.Spec.Replicas}}, nil
		}
		return true, d.DeepCopy(), nil
	})
	client.PrependReactor("patch", "deployments", func(a kt.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() != "scale" {
			t.Fatal("whole Deployment write")
		}
		*d.Spec.Replicas = 0
		return true, d.DeepCopy(), nil
	})
	store := &status.Store{Client: client, Namespace: "ns", Name: "status", UID: "status-uid"}
	engine := &Engine{Management: client, Store: store, Now: time.Now}
	if err := engine.consumer(context.Background(), config.Cluster{}, consumer, "generation", status.Consumer{}, nil, provider.IssuerCredential{}, provider.Transport, true); err != provider.Trust {
		t.Fatalf("unconfirmed stop: %v", err)
	}
	saved, err := store.Read(context.Background())
	entry := saved.Consumers[consumer.ID]
	if err != nil || *d.Spec.Replicas != 0 || !entry.StopLatched || entry.Condition != "StopUnconfirmed" {
		t.Fatal("unsupported accounting bypassed safety stop", err)
	}
	for _, a := range client.Actions() {
		if a.GetResource().Resource == "secrets" && a.GetVerb() != "get" {
			t.Fatal("published during unconfirmed stop")
		}
	}
}
