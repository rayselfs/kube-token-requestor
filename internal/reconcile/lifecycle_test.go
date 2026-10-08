package reconcile

import (
	"context"
	"fmt"
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

func TestStaleLeaderCannotPersistStopIntent(t *testing.T) {
	client := fake.NewClientset()
	e := &Engine{Management: client, Leader: func(context.Context) error { return provider.Conflict }}
	if err := e.stop(context.Background(), config.Consumer{}, &status.Consumer{}, "SafetyStopped"); err != provider.Conflict {
		t.Fatal("stale leader stop allowed")
	}
	if len(client.Actions()) != 0 {
		t.Fatal("stop mutation preceded leadership guard")
	}
}

func TestStaleGenerationCannotRestartCA(t *testing.T) {
	client := fake.NewClientset()
	e := &Engine{Management: client, Current: func(context.Context, string) error { return provider.Conflict }}
	if err := e.resume(context.Background(), config.Consumer{}, &status.Consumer{}, "stale"); err != provider.Conflict {
		t.Fatal("stale generation restart allowed")
	}
	if len(client.Actions()) != 0 {
		t.Fatal("restart mutation preceded generation guard")
	}
}

func TestReconfiguredRestartIntentLatchesStopped(t *testing.T) {
	for _, policy := range []string{"TokenFile", "StopStart"} {
		t.Run(policy, func(t *testing.T) {
			now := time.Unix(2000000000, 0)
			replicas := int32(0)
			digest := "sha256:" + strings.Repeat("1", 64)
			ca := []byte("public-test-ca")
			consumer := config.Consumer{ID: "consumer", ServiceAccount: config.ServiceAccount{Name: "ca", UID: "sa-uid"}, Secret: config.Ref{Namespace: "ns", Name: "output", UID: "output-uid"}, CADeployment: config.Deployment{Namespace: "ns", Name: "ca", UID: "deployment-uid", ImageDigest: digest}, ReloadPolicy: policy}
			cluster := config.Cluster{IdentityNamespace: "identity", CASHA256: credential.Hash(ca), Audiences: []string{"api"}, Lifetime: config.Lifetime{RenewBeforeSeconds: 300, StopBeforeSeconds: 60, ClockSkewSeconds: 5}}
			client := fake.NewClientset(&core.ConfigMap{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "status", UID: "status-uid"}}, &core.Secret{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "output", UID: "output-uid", Annotations: map[string]string{publish.Owner: "consumer"}}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"ca.crt": ca, "token": []byte(testutil.Token("system:serviceaccount:identity:ca", "identity", "ca", "sa-uid", []string{"api"}, now, 3600))}}, &apps.Deployment{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "ca", UID: "deployment-uid", Annotations: map[string]string{Acknowledge: "existing-operator-ack"}}, Spec: apps.DeploymentSpec{Replicas: &replicas, Template: core.PodTemplateSpec{Spec: core.PodSpec{Containers: []core.Container{{Image: "test@" + digest}}}}}})
			store := &status.Store{Client: client, Namespace: "ns", Name: "status", UID: "status-uid"}
			engine := &Engine{Management: client, Store: store, Now: func() time.Time { return now }}
			intentGeneration := "old-generation"
			if policy == "TokenFile" {
				intentGeneration = "current-generation"
			}
			entry := status.Consumer{Intent: &status.Intent{Generation: intentGeneration, DeploymentUID: "deployment-uid", Replicas: 1, Phase: "Published", CandidateExpiry: now.Add(time.Hour)}}
			if err := engine.consumer(context.Background(), cluster, consumer, "current-generation", entry, nil, provider.IssuerCredential{}, nil, true); err != nil {
				t.Fatal(err)
			}
			state, err := store.Read(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			recovered := state.Consumers[consumer.ID]
			if !recovered.StopLatched || recovered.Intent != nil || recovered.Acknowledgement != "existing-operator-ack" {
				t.Fatal("stale restart did not require a fresh acknowledgement")
			}
			for _, action := range client.Actions() {
				if action.GetVerb() == "patch" {
					t.Fatal("already stopped CA was mutated")
				}
			}
		})
	}
}

func TestManualScaleConflictCancelsRestartAuthority(t *testing.T) {
	replicas := int32(0)
	digest := "sha256:" + strings.Repeat("1", 64)
	consumer := config.Consumer{ID: "ca", CADeployment: config.Deployment{Namespace: "ns", Name: "ca", UID: "deployment-uid", ImageDigest: digest}}
	client := fake.NewClientset(&core.ConfigMap{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "status", UID: "status-uid"}}, &apps.Deployment{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "ca", UID: "deployment-uid", Annotations: map[string]string{Acknowledge: "previous-ack"}}, Spec: apps.DeploymentSpec{Replicas: &replicas, Template: core.PodTemplateSpec{Spec: core.PodSpec{Containers: []core.Container{{Image: "test@" + digest}}}}}})
	client.PrependReactor("get", "deployments", func(action kt.Action) (bool, runtime.Object, error) {
		if action.GetSubresource() != "scale" {
			return false, nil, nil
		}
		return true, &autoscaling.Scale{ObjectMeta: meta.ObjectMeta{UID: "deployment-uid"}, Spec: autoscaling.ScaleSpec{Replicas: 0}}, nil
	})
	store := &status.Store{Client: client, Namespace: "ns", Name: "status", UID: "status-uid"}
	engine := &Engine{Management: client, Store: store}
	entry := status.Consumer{Intent: &status.Intent{Generation: "current", DeploymentUID: "deployment-uid", Replicas: 1, Phase: "Stopping"}}
	if err := engine.save(context.Background(), consumer.ID, &entry); err != nil {
		t.Fatal(err)
	}
	// The earlier observation saw one replica; the fresh Scale sees the operator's zero.
	if err := engine.stopRenewal(context.Background(), consumer, &entry, 1); err != provider.Conflict {
		t.Fatal("competing scale was not reported", err)
	}
	state, err := store.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stopped := state.Consumers[consumer.ID]
	if !stopped.StopLatched || stopped.Intent != nil || stopped.Acknowledgement != "previous-ack" {
		t.Fatal("manual suspension retained automatic restart authority")
	}
	for _, action := range client.Actions() {
		if action.GetVerb() == "patch" {
			t.Fatal("already stopped deployment was modified")
		}
	}
}

func TestStartingConflictCancelsRestartAuthority(t *testing.T) {
	now := time.Unix(2000000000, 0)
	zero, one := int32(0), int32(1)
	digest := "sha256:" + strings.Repeat("1", 64)
	consumer := config.Consumer{ID: "ca", Secret: config.Ref{Name: "output"}, CADeployment: config.Deployment{Namespace: "ns", Name: "ca", UID: "deployment-uid", ImageDigest: digest}}
	d := &apps.Deployment{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "ca", UID: "deployment-uid"}, Spec: apps.DeploymentSpec{Replicas: &zero, Template: core.PodTemplateSpec{Spec: core.PodSpec{Containers: []core.Container{{Image: "test@" + digest, VolumeMounts: []core.VolumeMount{{Name: "identity", ReadOnly: true}}}}, Volumes: []core.Volume{{Name: "identity", VolumeSource: core.VolumeSource{Secret: &core.SecretVolumeSource{SecretName: "output"}}}}}}}}
	client := fake.NewClientset(&core.ConfigMap{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "status", UID: "status-uid"}}, d)
	reads := 0
	client.PrependReactor("get", "deployments", func(action kt.Action) (bool, runtime.Object, error) {
		reads++
		if reads != 1 {
			return false, nil, nil
		}
		active := d.DeepCopy()
		active.Spec.Replicas = &one
		return true, active, nil
	})
	store := &status.Store{Client: client, Namespace: "ns", Name: "status", UID: "status-uid"}
	engine := &Engine{Management: client, Store: store, Now: func() time.Time { return now }}
	entry := status.Consumer{Intent: &status.Intent{Generation: "current", DeploymentUID: "deployment-uid", Replicas: 1, Phase: "Published", CandidateExpiry: now.Add(time.Hour)}}
	if err := engine.save(context.Background(), consumer.ID, &entry); err != nil {
		t.Fatal(err)
	}
	if err := engine.resume(context.Background(), consumer, &entry, "current"); err != provider.Conflict {
		t.Fatal("operator stop during Starting was not reported", err)
	}
	state, err := store.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stopped := state.Consumers[consumer.ID]
	if !stopped.StopLatched || stopped.Intent != nil {
		t.Fatal("Starting conflict retained automatic restart authority")
	}
	for _, action := range client.Actions() {
		if action.GetVerb() == "patch" {
			t.Fatal("already stopped CA was changed")
		}
	}
}

func TestStatusOnlyScaleConflictsRetainRestart(t *testing.T) {
	for _, replicas := range []int32{0, 1} {
		t.Run(fmt.Sprint(replicas), func(t *testing.T) {
			now := time.Unix(2000000000, 0)
			digest := "sha256:" + strings.Repeat("1", 64)
			consumer := config.Consumer{ID: "ca", Secret: config.Ref{Name: "output"}, CADeployment: config.Deployment{Namespace: "ns", Name: "ca", UID: "deployment-uid", ImageDigest: digest}}
			d := &apps.Deployment{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "ca", UID: "deployment-uid", Generation: 4}, Spec: apps.DeploymentSpec{Replicas: &replicas, Template: core.PodTemplateSpec{Spec: core.PodSpec{Containers: []core.Container{{Image: "test@" + digest, VolumeMounts: []core.VolumeMount{{Name: "identity", ReadOnly: true}}}}, Volumes: []core.Volume{{Name: "identity", VolumeSource: core.VolumeSource{Secret: &core.SecretVolumeSource{SecretName: "output"}}}}}}}}
			client := fake.NewClientset(&core.ConfigMap{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "status", UID: "status-uid"}}, d)
			client.PrependReactor("get", "deployments", func(a kt.Action) (bool, runtime.Object, error) {
				if a.GetSubresource() != "scale" {
					return false, nil, nil
				}
				return true, &autoscaling.Scale{ObjectMeta: meta.ObjectMeta{UID: "deployment-uid", ResourceVersion: "before-status-update"}, Spec: autoscaling.ScaleSpec{Replicas: replicas}}, nil
			})
			client.PrependReactor("patch", "deployments", func(kt.Action) (bool, runtime.Object, error) { return true, nil, provider.Conflict })
			store := &status.Store{Client: client, Namespace: "ns", Name: "status", UID: "status-uid"}
			engine := &Engine{Management: client, Store: store, Now: func() time.Time { return now }}
			entry := status.Consumer{Intent: &status.Intent{Generation: "current", DeploymentUID: "deployment-uid", Replicas: 1, Phase: "Published", CandidateExpiry: now.Add(time.Hour)}}
			if err := engine.save(context.Background(), consumer.ID, &entry); err != nil {
				t.Fatal(err)
			}
			var err error
			if replicas == 0 {
				err = engine.resume(context.Background(), consumer, &entry, "current")
			} else {
				err = engine.stopRenewal(context.Background(), consumer, &entry, 1)
			}
			if err != provider.Conflict {
				t.Fatal("CAS conflict not returned", err)
			}
			state, err := store.Read(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			retained := state.Consumers[consumer.ID]
			if retained.StopLatched || retained.Intent == nil {
				t.Fatal("status-only conflict discarded owned restart")
			}
		})
	}
}
