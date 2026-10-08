package controller

import (
	"context"
	"encoding/json"

	"github.com/rayselfs/kube-token-requestor/internal/provider"
	coord "k8s.io/api/coordination/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

// Lock never creates or adopts a replaced Lease; RV protects overlapping renewals.
type Lock struct {
	Client                       kubernetes.Interface
	Namespace, Name, UID, Holder string
	last                         *coord.Lease
}

func (l *Lock) Get(ctx context.Context) (*resourcelock.LeaderElectionRecord, []byte, error) {
	object, err := l.Client.CoordinationV1().Leases(l.Namespace).Get(ctx, l.Name, meta.GetOptions{})
	if err != nil {
		return nil, nil, provider.Classify(err)
	}
	if string(object.UID) != l.UID {
		return nil, nil, provider.Trust
	}
	l.last = object
	record := resourcelock.LeaseSpecToLeaderElectionRecord(&object.Spec)
	data, err := json.Marshal(record)
	return record, data, err
}
func (l *Lock) Create(context.Context, resourcelock.LeaderElectionRecord) error {
	return provider.Trust
}
func (l *Lock) Update(ctx context.Context, record resourcelock.LeaderElectionRecord) error {
	if l.last == nil || string(l.last.UID) != l.UID {
		return provider.Trust
	}
	object := l.last.DeepCopy()
	object.Spec = resourcelock.LeaderElectionRecordToLeaseSpec(&record)
	updated, err := l.Client.CoordinationV1().Leases(l.Namespace).Update(ctx, object, meta.UpdateOptions{})
	if err == nil {
		l.last = updated
	}
	return provider.Classify(err)
}
func (l *Lock) RecordEvent(string) {}
func (l *Lock) Identity() string   { return l.Holder }
func (l *Lock) Describe() string   { return l.Namespace + "/" + l.Name }
