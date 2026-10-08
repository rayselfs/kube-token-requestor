package reconcile

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/status"
	apps "k8s.io/api/apps/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

const Acknowledge = "token-requestor.io/acknowledge-stop"

func deployment(ctx context.Context, client kubernetes.Interface, consumer config.Consumer) (*apps.Deployment, error) {
	d, err := client.AppsV1().Deployments(consumer.CADeployment.Namespace).Get(ctx, consumer.CADeployment.Name, meta.GetOptions{})
	if err != nil {
		return nil, provider.Classify(err)
	}
	if string(d.UID) != consumer.CADeployment.UID || d.Spec.Replicas == nil || *d.Spec.Replicas > 1 || len(d.Spec.Template.Spec.Containers) != 1 {
		return nil, provider.Trust
	}
	image := d.Spec.Template.Spec.Containers[0].Image
	if len(image) < len(consumer.CADeployment.ImageDigest)+1 || image[len(image)-len(consumer.CADeployment.ImageDigest)-1:] != "@"+consumer.CADeployment.ImageDigest {
		return nil, provider.Trust
	}
	return d, nil
}

func mounted(d *apps.Deployment, consumer config.Consumer) bool {
	mounted := false
	for _, volume := range d.Spec.Template.Spec.Volumes {
		if volume.Secret == nil || volume.Secret.SecretName != consumer.Secret.Name {
			continue
		}
		for _, mount := range d.Spec.Template.Spec.Containers[0].VolumeMounts {
			if mount.Name == volume.Name && mount.SubPath == "" && mount.SubPathExpr == "" && mount.ReadOnly {
				mounted = true
			}
		}
	}
	for _, variable := range d.Spec.Template.Spec.Containers[0].Env {
		if variable.ValueFrom != nil && variable.ValueFrom.SecretKeyRef != nil && variable.ValueFrom.SecretKeyRef.Name == consumer.Secret.Name {
			return false
		}
	}
	for _, source := range d.Spec.Template.Spec.Containers[0].EnvFrom {
		if source.SecretRef != nil && source.SecretRef.Name == consumer.Secret.Name {
			return false
		}
	}
	return mounted
}

func scale(ctx context.Context, client kubernetes.Interface, consumer config.Consumer, from, to int32) error {
	s, err := client.AppsV1().Deployments(consumer.CADeployment.Namespace).GetScale(ctx, consumer.CADeployment.Name, meta.GetOptions{})
	if err != nil {
		return provider.Classify(err)
	}
	if string(s.UID) != consumer.CADeployment.UID || s.Spec.Replicas != from {
		return provider.Conflict
	}
	patch, _ := json.Marshal([]map[string]any{
		{"op": "test", "path": "/metadata/uid", "value": consumer.CADeployment.UID},
		{"op": "test", "path": "/metadata/resourceVersion", "value": s.ResourceVersion},
		{"op": "test", "path": "/spec/replicas", "value": from},
		{"op": "replace", "path": "/spec/replicas", "value": to},
	})
	_, err = client.AppsV1().Deployments(consumer.CADeployment.Namespace).Patch(ctx, consumer.CADeployment.Name, types.JSONPatchType, patch, meta.PatchOptions{}, "scale")
	return provider.Classify(err)
}

func stopped(ctx context.Context, client kubernetes.Interface, consumer config.Consumer) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		d, err := deployment(ctx, client, consumer)
		if err != nil {
			return err
		}
		if *d.Spec.Replicas != 0 {
			return provider.Conflict
		}
		if d.Status.ObservedGeneration >= d.Generation && d.Status.Replicas == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return provider.Transport
		case <-ticker.C:
		}
	}
}

func (e *Engine) stop(ctx context.Context, consumer config.Consumer, entry *status.Consumer, condition string) error {
	if e.Leader != nil {
		if err := e.Leader(ctx); err != nil {
			return err
		}
	}
	// Intent survives crashes and latches before the stop request can be sent.
	entry.StopLatched, entry.Condition, entry.Intent = true, condition, nil
	if err := e.save(ctx, consumer.ID, entry); err != nil {
		return err
	}
	d, err := deployment(ctx, e.Management, consumer)
	if err != nil {
		return err
	}
	if *d.Spec.Replicas == 1 {
		if err := scale(ctx, e.Management, consumer, 1, 0); err != nil {
			return err
		}
	}
	err = stopped(ctx, e.Management, consumer)
	if err == nil {
		e.mu.Lock()
		delete(e.expiries, consumer.ID)
		e.mu.Unlock()
	}
	return err
}

func (e *Engine) resume(ctx context.Context, consumer config.Consumer, entry *status.Consumer, generation string) error {
	if e.Current != nil {
		if err := e.Current(ctx, generation); err != nil {
			return err
		}
	}
	intent := entry.Intent
	if intent == nil || intent.Generation != generation || intent.DeploymentUID != consumer.CADeployment.UID || intent.Replicas != 1 ||
		entry.StopLatched || intent.Phase != "Published" || !intent.CandidateExpiry.After(e.Now().Add(5*time.Minute)) {
		return provider.Trust
	}
	d, err := deployment(ctx, e.Management, consumer)
	if err != nil {
		return err
	}
	if !mounted(d, consumer) {
		return provider.Trust
	}
	entry.Intent.Phase = "Starting"
	if err := e.save(ctx, consumer.ID, entry); err != nil {
		return err
	}
	if e.Current != nil {
		if err := e.Current(ctx, generation); err != nil {
			return err
		}
	}
	if *d.Spec.Replicas == 0 {
		if err := scale(ctx, e.Management, consumer, 0, 1); err != nil {
			return err
		}
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		current, err := deployment(ctx, e.Management, consumer)
		if err != nil {
			return err
		}
		if *current.Spec.Replicas != 1 {
			return provider.Conflict
		}
		if current.Status.ObservedGeneration >= current.Generation && current.Status.ReadyReplicas == 1 {
			break
		}
		select {
		case <-ctx.Done():
			return provider.Transport
		case <-ticker.C:
		}
	}
	entry.Intent, entry.Condition = nil, "Healthy"
	return e.save(ctx, consumer.ID, entry)
}

// A known competing scale operation cancels our restart authority. Indeterminate transport
// failures keep durable intent for crash recovery; operators disable the consumer to suspend it.
func (e *Engine) stopRenewal(ctx context.Context, consumer config.Consumer, entry *status.Consumer, replicas int32) error {
	var err error
	if replicas == 1 {
		err = scale(ctx, e.Management, consumer, 1, 0)
	}
	if err == nil {
		err = stopped(ctx, e.Management, consumer)
	}
	if err != provider.Conflict {
		return err
	}
	d, readErr := deployment(ctx, e.Management, consumer)
	if readErr != nil {
		return readErr
	}
	entry.Acknowledgement = d.Annotations[Acknowledge]
	if stopErr := e.stop(ctx, consumer, entry, "SafetyStopped"); stopErr != nil {
		return stopErr
	}
	return provider.Conflict
}
