package reconcile

import (
	"context"
	"encoding/json"
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

func haFixture(replicas int32) (config.Consumer, *apps.Deployment) {
	limit := int32(2)
	c := config.Consumer{ID: "ca", Secret: config.Ref{Name: "output"}, PermissionProfile: "ca-read-events-lease", LeaderElectionLease: &config.Ref{Namespace: "identity", Name: "ca-leader", UID: "lease-uid"}, CADeployment: config.Deployment{Namespace: "ns", Name: "ca", UID: "deployment-uid", ImageDigest: "sha256:" + strings.Repeat("1", 64), MaxReplicas: &limit}}
	d := &apps.Deployment{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "ca", UID: "deployment-uid", Generation: 1}, Spec: apps.DeploymentSpec{Replicas: &replicas, Template: core.PodTemplateSpec{Spec: core.PodSpec{Containers: []core.Container{{Image: "test@" + c.CADeployment.ImageDigest, Args: []string{"--leader-elect=true", "--leader-elect-resource-lock=leases", "--leader-elect-resource-name=ca-leader", "--namespace=identity"}, VolumeMounts: []core.VolumeMount{{Name: "token", ReadOnly: true}}}}, Volumes: []core.Volume{{Name: "token", VolumeSource: core.VolumeSource{Secret: &core.SecretVolumeSource{SecretName: "output"}}}}}}}, Status: apps.DeploymentStatus{ObservedGeneration: 1, Replicas: replicas, ReadyReplicas: replicas, TerminatingReplicas: new(int32)}}
	return c, d
}

func TestHADeploymentRejectsUndeclaredOrWrongElection(t *testing.T) {
	for _, mode := range []string{"valid", "default-limit", "wrong-namespace", "duplicate-election", "wrong-lease", "three"} {
		t.Run(mode, func(t *testing.T) {
			c, d := haFixture(2)
			switch mode {
			case "default-limit":
				c.CADeployment.MaxReplicas = nil
			case "wrong-namespace":
				d.Spec.Template.Spec.Containers[0].Args[3] = "--namespace=other"
			case "duplicate-election":
				d.Spec.Template.Spec.Containers[0].Args = append(d.Spec.Template.Spec.Containers[0].Args, "--leader-elect=false")
			case "wrong-lease":
				d.Spec.Template.Spec.Containers[0].Args[2] = "--leader-elect-resource-name=other"
			case "three":
				*d.Spec.Replicas = 3
			}
			client := fake.NewClientset(d)
			_, err := deployment(context.Background(), client, c)
			if (err == nil) != (mode == "valid") {
				t.Fatal("HA trust boundary incorrect")
			}
			for _, a := range client.Actions() {
				if a.GetVerb() == "patch" {
					t.Fatal("preflight mutated CA")
				}
			}
		})
	}
}

func TestHAResumeRestoresDurableTwoReplicaIntent(t *testing.T) {
	c, d := haFixture(0)
	now := time.Unix(2000000000, 0)
	client := fake.NewClientset(d, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "status", UID: "status-uid"}})
	client.PrependReactor("get", "deployments", func(a kt.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() == "scale" {
			return true, &autoscaling.Scale{ObjectMeta: meta.ObjectMeta{UID: d.UID, ResourceVersion: "10"}, Spec: autoscaling.ScaleSpec{Replicas: *d.Spec.Replicas}}, nil
		}
		return true, d.DeepCopy(), nil
	})
	client.PrependReactor("patch", "deployments", func(a kt.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() != "scale" {
			t.Fatal("whole Deployment write")
		}
		patch := string(a.(kt.PatchAction).GetPatch())
		if !strings.Contains(patch, `"value":2`) || !strings.Contains(patch, `"/metadata/resourceVersion"`) {
			t.Fatal("lost replica/CAS intent")
		}
		*d.Spec.Replicas = 2
		d.Status.Replicas = 2
		d.Status.ReadyReplicas = 2
		return true, d.DeepCopy(), nil
	})
	e := &Engine{Management: client, Store: &status.Store{Client: client, Namespace: "ns", Name: "status", UID: "status-uid"}, Now: func() time.Time { return now }}
	entry := status.Consumer{Intent: &status.Intent{Generation: "generation", DeploymentUID: "deployment-uid", Replicas: 2, CandidateExpiry: now.Add(time.Hour), Phase: "Published"}}
	if err := e.resume(context.Background(), c, &entry, "generation"); err != nil {
		t.Fatal(err)
	}
	if *d.Spec.Replicas != 2 || entry.Intent != nil || entry.Condition != "Healthy" {
		t.Fatal("two replica restart not completed")
	}
}

func TestHACannotRestoreBeyondDeclaredLimit(t *testing.T) {
	c, d := haFixture(0)
	c.CADeployment.MaxReplicas = nil
	client := fake.NewClientset(d)
	e := &Engine{Management: client, Now: time.Now}
	entry := status.Consumer{Intent: &status.Intent{Generation: "generation", DeploymentUID: "deployment-uid", Replicas: 2, CandidateExpiry: time.Now().Add(time.Hour), Phase: "Published"}}
	if err := e.resume(context.Background(), c, &entry, "generation"); err != provider.Trust {
		t.Fatal("foreign replica intent accepted")
	}
	if len(client.Actions()) != 0 {
		t.Fatal("unapproved replica mode contacted API")
	}
}

func TestHAScaleRejectsOutOfBoundsBeforeAPI(t *testing.T) {
	c, _ := haFixture(0)
	for _, counts := range [][2]int32{{-1, 0}, {0, -1}, {3, 0}, {0, 3}} {
		client := fake.NewClientset()
		if err := scale(context.Background(), client, c, counts[0], counts[1]); err != provider.Trust {
			t.Fatal("unbounded scale accepted", counts, err)
		}
		if len(client.Actions()) != 0 {
			t.Fatal("unbounded scale contacted API")
		}
	}
}

func TestHASafetyStopPersistsLatchBeforeStoppingBothReplicas(t *testing.T) {
	c, d := haFixture(2)
	client := fake.NewClientset(d, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "status", UID: "status-uid"}})
	store := &status.Store{Client: client, Namespace: "ns", Name: "status", UID: "status-uid"}
	client.PrependReactor("get", "deployments", func(a kt.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() == "scale" {
			return true, &autoscaling.Scale{ObjectMeta: meta.ObjectMeta{UID: d.UID, ResourceVersion: "10"}, Spec: autoscaling.ScaleSpec{Replicas: *d.Spec.Replicas}}, nil
		}
		return true, d.DeepCopy(), nil
	})
	client.PrependReactor("patch", "deployments", func(a kt.Action) (bool, runtime.Object, error) {
		record, err := client.Tracker().Get(schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}, "ns", "status")
		var saved status.Snapshot
		if err != nil || json.Unmarshal([]byte(record.(*core.ConfigMap).Data["state.json"]), &saved) != nil || !saved.Consumers[c.ID].StopLatched {
			t.Fatal("scale preceded durable safety latch")
		}
		if a.GetSubresource() != "scale" {
			t.Fatal("whole Deployment write")
		}
		*d.Spec.Replicas = 0
		d.Status.Replicas, d.Status.ReadyReplicas = 0, 0
		return true, d.DeepCopy(), nil
	})
	e := &Engine{Management: client, Store: store}
	entry := status.Consumer{}
	if err := e.stop(context.Background(), c, &entry, "SafetyStopped"); err != nil {
		t.Fatal(err)
	}
	if *d.Spec.Replicas != 0 || !entry.StopLatched {
		t.Fatal("HA safety stop incomplete")
	}
}
