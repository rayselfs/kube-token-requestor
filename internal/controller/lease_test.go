package controller

import (
	"context"
	"testing"

	"github.com/rayselfs/kube-token-requestor/internal/provider"
	coord "k8s.io/api/coordination/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

func TestPinnedLease(t *testing.T) {
	client := fake.NewClientset(&coord.Lease{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "lease", UID: "original"}})
	l := &Lock{Client: client, Namespace: "ns", Name: "lease", UID: "original", Holder: "test-pod"}
	if _, _, err := l.Get(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := l.Update(context.Background(), resourcelock.LeaderElectionRecord{HolderIdentity: "test-pod"}); err != nil {
		t.Fatal(err)
	}
	l.UID = "replacement"
	if _, _, err := l.Get(context.Background()); err != provider.Trust {
		t.Fatal("replaced lease adopted")
	}
	if err := l.Create(context.Background(), resourcelock.LeaderElectionRecord{}); err != provider.Trust {
		t.Fatal("lease creation permitted")
	}
}
