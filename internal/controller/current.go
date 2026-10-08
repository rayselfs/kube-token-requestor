package controller

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// current rechecks live pins at publication boundaries; cross-object atomic fencing is not promised.
func (r *runtime) current(ctx context.Context, generation string) error {
	if ctx.Err() != nil {
		return provider.Transport
	}
	if err := r.leader(ctx); err != nil {
		return err
	}
	object, err := r.client.CoreV1().ConfigMaps(r.opts.Namespace).Get(ctx, r.opts.Registry, meta.GetOptions{})
	if err != nil {
		return provider.Classify(err)
	}
	if string(object.UID) != r.registryUID {
		return provider.Trust
	}
	parsed, err := config.Parse(strings.NewReader(object.Data["registry.json"]))
	if err != nil {
		return provider.Trust
	}
	data, err := json.Marshal(parsed)
	if err != nil || credential.Hash(data) != generation {
		return provider.Conflict
	}
	state, err := r.engine.Store.Read(ctx)
	if err != nil {
		return err
	}
	if state.Generation != generation {
		return provider.Conflict
	}
	return nil
}

func (r *runtime) leader(ctx context.Context) error {
	if ctx.Err() != nil {
		return provider.Transport
	}
	lease, err := r.client.CoordinationV1().Leases(r.opts.Namespace).Get(ctx, r.opts.Lease, meta.GetOptions{})
	if err != nil {
		return provider.Classify(err)
	}
	if string(lease.UID) != r.leaseUID || lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != r.opts.Identity {
		return provider.Conflict
	}
	return nil
}
