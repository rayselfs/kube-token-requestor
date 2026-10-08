package controller

import (
	"context"
	"reflect"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (r *runtime) transition(ctx context.Context, next *config.Registry) error {
	if r.registry == nil {
		return nil
	}
	for _, old := range r.registry.Clusters {
		var replacement *config.Cluster
		for i := range next.Clusters {
			if next.Clusters[i].ID == old.ID {
				replacement = &next.Clusters[i]
				break
			}
		}
		if replacement != nil {
			if old.Endpoint != replacement.Endpoint || old.KubeSystemUID != replacement.KubeSystemUID || old.CASHA256 != replacement.CASHA256 || old.IdentityNamespace != replacement.IdentityNamespace {
				return provider.Trust
			}
			if !reflect.DeepEqual(old.Provider, replacement.Provider) || !reflect.DeepEqual(old.ExpectedIssuer, replacement.ExpectedIssuer) || !reflect.DeepEqual(old.Audiences, replacement.Audiences) || old.Lifetime != replacement.Lifetime {
				if *old.Enabled || *replacement.Enabled {
					return provider.Trust
				}
				for _, consumer := range old.Consumers {
					if err := r.drained(ctx, consumer); err != nil {
						return err
					}
				}
			}
		}
		for _, consumer := range old.Consumers {
			var enrolled *config.Consumer
			if replacement != nil {
				for i := range replacement.Consumers {
					if replacement.Consumers[i].ID == consumer.ID {
						enrolled = &replacement.Consumers[i]
						break
					}
				}
			}
			if enrolled == nil {
				if err := r.drained(ctx, consumer); err != nil {
					return err
				}
				continue
			}
			if !reflect.DeepEqual(consumer.Secret, enrolled.Secret) || !reflect.DeepEqual(consumer.ServiceAccount, enrolled.ServiceAccount) || consumer.CADeployment.Namespace != enrolled.CADeployment.Namespace || consumer.CADeployment.Name != enrolled.CADeployment.Name || consumer.CADeployment.UID != enrolled.CADeployment.UID {
				return provider.Trust
			}
			if consumer.ReloadPolicy != enrolled.ReloadPolicy || consumer.CADeployment.ImageDigest != enrolled.CADeployment.ImageDigest {
				if *enrolled.Enabled {
					return provider.Trust
				}
				if err := r.drained(ctx, consumer); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func (r *runtime) drained(ctx context.Context, consumer config.Consumer) error {
	if *consumer.Enabled {
		return provider.Trust
	}
	d, err := r.client.AppsV1().Deployments(consumer.CADeployment.Namespace).Get(ctx, consumer.CADeployment.Name, meta.GetOptions{})
	if err != nil {
		return provider.Classify(err)
	}
	if string(d.UID) != consumer.CADeployment.UID || d.Spec.Replicas == nil || *d.Spec.Replicas != 0 || d.Status.Replicas != 0 || d.Status.ObservedGeneration < d.Generation {
		return provider.Trust
	}
	s, err := r.engine.Store.Read(ctx)
	if err != nil {
		return err
	}
	if s.Consumers[consumer.ID].Intent != nil {
		return provider.Trust
	}
	return nil
}
