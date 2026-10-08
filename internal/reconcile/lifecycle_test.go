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
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	kt "k8s.io/client-go/testing"
)

func TestStopNeverPrecedesDurableIntent(t *testing.T) {
	client := fake.NewClientset(&core.ConfigMap{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "status", UID: "status-uid"}})
	client.PrependReactor("update", "configmaps", func(kt.Action) (bool, runtime.Object, error) { return true, nil, provider.Auth })
	engine := &Engine{Management: client, Store: &status.Store{Client: client, Namespace: "ns", Name: "status", UID: "status-uid"}}
	if err := engine.stop(context.Background(), config.Consumer{ID: "consumer"}, &status.Consumer{}, "SafetyStopped"); err != provider.Auth {
		t.Fatal("persistence failure ignored")
	}
	for _, action := range client.Actions() {
		if action.GetResource().Resource == "deployments" {
			t.Fatal("CA touched before persistence")
		}
	}
}
func TestStoppedConsumerNeverAutoStarts(t *testing.T) {
	now := time.Unix(2000000000, 0)
	replicas := int32(0)
	digest := "sha256:" + strings.Repeat("1", 64)
	consumer := config.Consumer{ID: "consumer", ServiceAccount: config.ServiceAccount{Name: "ca", UID: "sa-uid"}, Secret: config.Ref{Namespace: "ns", Name: "output", UID: "output-uid"}, CADeployment: config.Deployment{Namespace: "ns", Name: "ca", UID: "deployment-uid", ImageDigest: digest}, ReloadPolicy: "StopStart"}
	ca := []byte("public-test-ca")
	c := config.Cluster{IdentityNamespace: "identity", CASHA256: credential.Hash(ca), Audiences: []string{"api"}, Lifetime: config.Lifetime{RenewBeforeSeconds: 300, StopBeforeSeconds: 60, ClockSkewSeconds: 5}}
	client := fake.NewClientset(&core.ConfigMap{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "status", UID: "status-uid"}}, &core.Secret{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "output", UID: "output-uid", Annotations: map[string]string{publish.Owner: "consumer"}}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"ca.crt": ca, "token": []byte(testutil.Token("system:serviceaccount:identity:ca", "identity", "ca", "sa-uid", []string{"api"}, now, 3600))}}, &apps.Deployment{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "ca", UID: "deployment-uid"}, Spec: apps.DeploymentSpec{Replicas: &replicas, Template: core.PodTemplateSpec{Spec: core.PodSpec{Containers: []core.Container{{Image: "test@" + digest}}}}}})
	engine := &Engine{Management: client, Store: &status.Store{Client: client, Namespace: "ns", Name: "status", UID: "status-uid"}, Now: func() time.Time { return now }}
	if err := engine.consumer(context.Background(), c, consumer, "generation", status.Consumer{}, nil, provider.IssuerCredential{}, nil, true); err != nil && err != provider.Trust {
		t.Fatal(err)
	}
	for _, action := range client.Actions() {
		if action.GetVerb() == "patch" {
			t.Fatal("stopped CA auto-started")
		}
	}
}

func TestRetryNeverCrossesSafetyDeadline(t *testing.T) {
	now := time.Unix(2000000000, 0)
	e := &Engine{Now: func() time.Time { return now }, expiries: map[string]time.Time{"ca": now.Add(70 * time.Second)}}
	c := config.Cluster{Consumers: []config.Consumer{{ID: "ca"}}, Lifetime: config.Lifetime{StopBeforeSeconds: 60, ClockSkewSeconds: 5}}
	if got := e.Delay(c, 5*time.Minute); got != 5*time.Second {
		t.Fatalf("unsafe retry delay: %s", got)
	}
	e.expiries["ca"] = now
	if got := e.Delay(c, 5*time.Minute); got != time.Second {
		t.Fatalf("deadline hot loop: %s", got)
	}
	delete(e.expiries, "ca")
	if got := e.Delay(c, 5*time.Minute); got != 5*time.Minute {
		t.Fatalf("inactive CA changed backoff: %s", got)
	}
}

func TestStaleLeaderCannotOverwriteSafetyLatch(t *testing.T) {
	client := fake.NewClientset(&core.ConfigMap{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "status", UID: "status-uid"}})
	store := &status.Store{Client: client, Namespace: "ns", Name: "status", UID: "status-uid"}
	e := &Engine{Store: store}
	stale := status.Consumer{Condition: "Healthy"}
	current := status.Consumer{Condition: "SafetyStopped", StopLatched: true}
	if err := e.save(context.Background(), "ca", &current); err != nil {
		t.Fatal(err)
	}
	if err := e.save(context.Background(), "ca", &stale); err != provider.Conflict {
		t.Fatal("stale leader erased safety latch")
	}
	state, err := store.Read(context.Background())
	if err != nil || !state.Consumers["ca"].StopLatched {
		t.Fatal("durable latch lost")
	}
	current.Condition = "StopUnconfirmed"
	if err := e.save(context.Background(), "ca", &current); err != nil {
		t.Fatal("own subsequent update failed", err)
	}
}
