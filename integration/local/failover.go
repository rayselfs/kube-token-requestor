package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/publish"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// failover deletes only the UID-pinned leader Pod in the guarded synthetic fixture.
// It does not mutate nodes, credentials, workload policy, Lease or durable status.
func failover(root, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return provider.Trust
	}
	var values struct {
		Registry config.Registry `json:"registry"`
	}
	if json.Unmarshal(data, &values) != nil || values.Registry.Validate() != nil || len(values.Registry.Clusters) != 2 {
		return provider.Trust
	}
	management, _, err := local(root, "management")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	const namespace, name = "requestor-test", "requestor-kube-token-requestor"
	system, err := management.CoreV1().Namespaces().Get(ctx, "kube-system", meta.GetOptions{})
	if err != nil || string(system.UID) != values.Registry.ManagementUID {
		return provider.Trust
	}
	deployment, err := management.AppsV1().Deployments(namespace).Get(ctx, name, meta.GetOptions{})
	if err != nil || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 2 || deployment.Status.ReadyReplicas != 2 || len(deployment.Spec.Template.Spec.Containers) != 1 {
		return provider.Trust
	}
	image := deployment.Spec.Template.Spec.Containers[0].Image
	if !strings.HasPrefix(image, "ghcr.io/rayselfs/kube-token-requestor@sha256:") || len(image) != len("ghcr.io/rayselfs/kube-token-requestor@sha256:")+64 {
		return provider.Trust
	}
	lease, err := management.CoordinationV1().Leases(namespace).Get(ctx, name, meta.GetOptions{})
	if err != nil || lease.Spec.HolderIdentity == nil || lease.Spec.RenewTime == nil || time.Since(lease.Spec.RenewTime.Time) > 20*time.Second {
		return provider.Trust
	}
	pods, err := management.CoreV1().Pods(namespace).List(ctx, meta.ListOptions{LabelSelector: "app.kubernetes.io/name=kube-token-requestor,app.kubernetes.io/instance=requestor"})
	if err != nil || len(pods.Items) != 2 {
		return provider.Trust
	}
	var leader *core.Pod
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Spec.ServiceAccountName != name || len(pod.Spec.Containers) != 1 || pod.Spec.Containers[0].Image != image || pod.DeletionTimestamp != nil {
			return provider.Trust
		}
		if string(pod.UID) == *lease.Spec.HolderIdentity {
			leader = pod
		}
	}
	if leader == nil {
		return provider.Trust
	}
	status, err := management.CoreV1().ConfigMaps(namespace).Get(ctx, name+"-status", meta.GetOptions{})
	if err != nil {
		return provider.Trust
	}
	type prior struct {
		hash   string
		expiry time.Time
	}
	outputs := map[string]prior{}
	var caUID string
	for _, cluster := range values.Registry.Clusters {
		if cluster.Provider.Type != "SecretIssuer" || cluster.Lifetime.RequestedSeconds != 600 || cluster.Lifetime.RenewBeforeSeconds != 570 {
			return provider.Trust
		}
		for _, consumer := range cluster.Consumers {
			output, err := publish.Read(ctx, management, consumer)
			if err != nil || len(output.Data["token"]) == 0 || publish.StoredExpiry(output, cluster, consumer).Before(time.Now().Add(3*time.Minute)) {
				return provider.Trust
			}
			outputs[consumer.ID] = prior{credential.Hash(output.Data["token"]), publish.StoredExpiry(output, cluster, consumer)}
			ca, err := management.AppsV1().Deployments(consumer.CADeployment.Namespace).Get(ctx, consumer.CADeployment.Name, meta.GetOptions{})
			if err != nil || string(ca.UID) != consumer.CADeployment.UID || ca.Spec.Replicas == nil {
				return provider.Trust
			}
			if cluster.ID == "child-a" && consumer.ID == "child-a-ca-one" {
				active, err := management.CoreV1().Pods(namespace).List(ctx, meta.ListOptions{LabelSelector: "app=" + consumer.ID})
				if err != nil || *ca.Spec.Replicas != 1 || len(active.Items) != 1 {
					return provider.Trust
				}
				caUID = string(active.Items[0].UID)
			} else if *ca.Spec.Replicas != 0 {
				return provider.Trust
			}
		}
	}
	if caUID == "" || len(outputs) != 3 {
		return provider.Trust
	}
	zero, uid := int64(0), leader.UID
	started := time.Now()
	if management.CoreV1().Pods(namespace).Delete(ctx, leader.Name, meta.DeleteOptions{GracePeriodSeconds: &zero, Preconditions: &meta.Preconditions{UID: &uid}}) != nil {
		return provider.Transport
	}
	deadline := time.Now().Add(90 * time.Second)
	for {
		current, err := management.CoordinationV1().Leases(namespace).Get(ctx, name, meta.GetOptions{})
		if err == nil && current.UID == lease.UID && current.Spec.HolderIdentity != nil && *current.Spec.HolderIdentity != string(uid) {
			ready, err := management.CoreV1().Pods(namespace).List(ctx, meta.ListOptions{LabelSelector: "app.kubernetes.io/name=kube-token-requestor,app.kubernetes.io/instance=requestor"})
			if err == nil && len(ready.Items) == 2 {
				count, holder := 0, false
				for _, pod := range ready.Items {
					if len(pod.Status.ContainerStatuses) == 1 && pod.Status.ContainerStatuses[0].Ready && pod.Status.ContainerStatuses[0].RestartCount == 0 && pod.Spec.Containers[0].Image == image {
						count++
						holder = holder || string(pod.UID) == *current.Spec.HolderIdentity
					}
				}
				if count == 2 && holder {
					break
				}
			}
		}
		if !time.Now().Before(deadline) {
			return provider.Transport
		}
		if waitLocal(ctx, time.Second) != nil {
			return provider.Transport
		}
	}
	failoverSeconds := time.Since(started).Seconds()
	for {
		rotated := 0
		for _, cluster := range values.Registry.Clusters {
			for _, consumer := range cluster.Consumers {
				output, err := publish.Read(ctx, management, consumer)
				if err != nil || publish.StoredExpiry(output, cluster, consumer).Before(outputs[consumer.ID].expiry) {
					return provider.Trust
				}
				if credential.Hash(output.Data["token"]) != outputs[consumer.ID].hash {
					rotated++
				}
			}
		}
		if rotated == len(outputs) {
			break
		}
		if waitLocal(ctx, time.Second) != nil {
			return provider.Transport
		}
	}
	after, err := management.CoreV1().ConfigMaps(namespace).Get(ctx, name+"-status", meta.GetOptions{})
	if err != nil || after.UID != status.UID {
		return provider.Trust
	}
	actual, err := management.AppsV1().Deployments(namespace).Get(ctx, name, meta.GetOptions{})
	if err != nil || actual.UID != deployment.UID || actual.Spec.Replicas == nil || *actual.Spec.Replicas != 2 {
		return provider.Trust
	}
	active, err := management.CoreV1().Pods(namespace).List(ctx, meta.ListOptions{LabelSelector: "app=child-a-ca-one"})
	if err != nil || len(active.Items) != 1 || string(active.Items[0].UID) != caUID || len(active.Items[0].Status.ContainerStatuses) != 1 || !active.Items[0].Status.ContainerStatuses[0].Ready || active.Items[0].Status.ContainerStatuses[0].RestartCount != 0 {
		return provider.Trust
	}
	if err := assert(root, path, true); err != nil {
		return err
	}
	fmt.Printf("synthetic leader loss passed: failover within %.1fs, all three outputs renewed without expiry rollback, durable state and actual CA Pod retained\n", failoverSeconds)
	return nil
}
