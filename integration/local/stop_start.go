package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/publish"
	"github.com/rayselfs/kube-token-requestor/internal/status"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// stopStart exercises only the initially stopped second synthetic consumer.
func stopStart(root, path string) (result error) {
	phase := "input-validation"
	defer func() {
		if result != nil {
			fmt.Println("local StopStart failure phase:", phase)
		}
	}()
	data, err := os.ReadFile(path)
	if err != nil {
		return provider.Trust
	}
	var values struct {
		Registry config.Registry `json:"registry"`
	}
	if json.Unmarshal(data, &values) != nil || values.Registry.Validate() != nil {
		return provider.Trust
	}
	if len(values.Registry.Clusters) != 2 || values.Registry.Clusters[0].ID != "child-a" || len(values.Registry.Clusters[0].Consumers) != 2 {
		return provider.Trust
	}
	consumer := values.Registry.Clusters[0].Consumers[1]
	if consumer.ID != "child-a-ca-two" || consumer.ReloadPolicy != "TokenFile" || !*consumer.Enabled || values.Registry.Clusters[0].Lifetime.RenewBeforeSeconds != 570 {
		return provider.Trust
	}
	management, _, err := local(root, "management")
	if err != nil {
		return err
	}
	child, _, err := local(root, "child-a")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	uid, err := management.CoreV1().Namespaces().Get(ctx, "kube-system", meta.GetOptions{})
	if err != nil || string(uid.UID) != values.Registry.ManagementUID {
		return provider.Trust
	}
	uid, err = child.CoreV1().Namespaces().Get(ctx, "kube-system", meta.GetOptions{})
	if err != nil || string(uid.UID) != values.Registry.Clusters[0].KubeSystemUID {
		return provider.Trust
	}
	ns := consumer.CADeployment.Namespace
	d, err := management.AppsV1().Deployments(ns).Get(ctx, consumer.CADeployment.Name, meta.GetOptions{})
	if err != nil || string(d.UID) != consumer.CADeployment.UID || d.Spec.Replicas == nil || *d.Spec.Replicas != 0 || d.Status.Replicas != 0 {
		return provider.Trust
	}
	registryName := "requestor-kube-token-requestor-registry"
	object, err := management.CoreV1().ConfigMaps(ns).Get(ctx, registryName, meta.GetOptions{})
	if err != nil {
		return provider.Trust
	}
	registryUID := object.UID
	originalRegistry := object.Data["registry.json"]
	controller, err := management.AppsV1().Deployments(ns).Get(ctx, "requestor-kube-token-requestor", meta.GetOptions{})
	if err != nil || controller.Spec.Replicas == nil || *controller.Spec.Replicas != 2 || controller.Status.ReadyReplicas != 2 {
		return provider.Trust
	}
	controllerUID := controller.UID
	paused := false
	controllerReplicas := func(call context.Context, replicas int32) error {
		d, err := management.AppsV1().Deployments(ns).Get(call, controller.Name, meta.GetOptions{})
		if err != nil || d.UID != controllerUID {
			return provider.Trust
		}
		patch, _ := json.Marshal([]map[string]any{{"op": "test", "path": "/metadata/uid", "value": string(controllerUID)}, {"op": "test", "path": "/metadata/resourceVersion", "value": d.ResourceVersion}, {"op": "replace", "path": "/spec/replicas", "value": replicas}})
		if _, err := management.AppsV1().Deployments(ns).Patch(call, d.Name, types.JSONPatchType, patch, meta.PatchOptions{FieldManager: "helm"}); err != nil {
			return provider.Classify(err)
		}
		paused = replicas == 0
		for range 60 {
			d, err := management.AppsV1().Deployments(ns).Get(call, controller.Name, meta.GetOptions{})
			if err != nil || d.UID != controllerUID {
				return provider.Trust
			}
			if d.Status.ObservedGeneration >= d.Generation && replicas == 2 && d.Status.ReadyReplicas == 2 {
				return nil
			}
			if replicas == 0 && d.Status.Replicas == 0 {
				pods, err := management.CoreV1().Pods(ns).List(call, meta.ListOptions{LabelSelector: "app.kubernetes.io/name=kube-token-requestor,app.kubernetes.io/instance=requestor"})
				if err != nil {
					return provider.Classify(err)
				}
				if len(pods.Items) == 0 {
					return nil
				}
			}
			if err := waitLocal(call, 2*time.Second); err != nil {
				return err
			}
		}
		return provider.Transport
	}
	state, err := management.CoreV1().ConfigMaps(ns).Get(ctx, "requestor-kube-token-requestor-status", meta.GetOptions{})
	if err != nil {
		return provider.Trust
	}
	var initial status.Snapshot
	if json.Unmarshal([]byte(state.Data["state.json"]), &initial) != nil || initial.Consumers[consumer.ID].StopLatched || initial.Consumers[consumer.ID].Intent != nil {
		return provider.Trust
	}
	var current config.Registry
	if json.Unmarshal([]byte(object.Data["registry.json"]), &current) != nil {
		return provider.Trust
	}
	want, _ := json.Marshal(values.Registry)
	have, _ := json.Marshal(current)
	if string(want) != string(have) {
		return provider.Conflict
	}
	expectedGeneration := credential.Hash(have)
	set := func(call context.Context, enabled bool, policy string) error {
		object, err := management.CoreV1().ConfigMaps(ns).Get(call, registryName, meta.GetOptions{})
		if err != nil || object.UID != registryUID {
			return provider.Trust
		}
		var registry config.Registry
		if json.Unmarshal([]byte(object.Data["registry.json"]), &registry) != nil {
			return provider.Trust
		}
		before, _ := json.Marshal(registry)
		if credential.Hash(before) != expectedGeneration {
			return provider.Conflict
		}
		registry.Clusters[0].Consumers[1].Enabled = &enabled
		registry.Clusters[0].Consumers[1].ReloadPolicy = policy
		if registry.Validate() != nil {
			return provider.Trust
		}
		after, _ := json.Marshal(registry)
		object.Data["registry.json"] = string(after)
		if enabled && policy == "TokenFile" {
			object.Data["registry.json"] = originalRegistry
		}
		// Return fixture fields to their existing Helm owner; no second production writer is introduced.
		if _, err := management.CoreV1().ConfigMaps(ns).Update(call, object, meta.UpdateOptions{FieldManager: "helm"}); err != nil {
			return provider.Classify(err)
		}
		expectedGeneration = credential.Hash(after)
		if paused {
			return nil
		}
		deadline := time.Now().Add(75 * time.Second)
		for time.Now().Before(deadline) {
			s, err := management.CoreV1().ConfigMaps(ns).Get(call, "requestor-kube-token-requestor-status", meta.GetOptions{})
			if err != nil {
				return provider.Classify(err)
			}
			var snapshot status.Snapshot
			if json.Unmarshal([]byte(s.Data["state.json"]), &snapshot) != nil {
				return provider.Trust
			}
			if snapshot.Generation == expectedGeneration {
				return nil
			}
			if err := waitLocal(call, 2*time.Second); err != nil {
				return err
			}
		}
		return provider.Transport
	}
	scale := func(call context.Context, replicas int32) error {
		d, err := management.AppsV1().Deployments(ns).Get(call, consumer.CADeployment.Name, meta.GetOptions{})
		if err != nil || string(d.UID) != consumer.CADeployment.UID {
			return provider.Trust
		}
		patch, _ := json.Marshal([]map[string]any{{"op": "test", "path": "/metadata/uid", "value": consumer.CADeployment.UID}, {"op": "test", "path": "/metadata/resourceVersion", "value": d.ResourceVersion}, {"op": "replace", "path": "/spec/replicas", "value": replicas}})
		_, err = management.AppsV1().Deployments(ns).Patch(call, d.Name, types.JSONPatchType, patch, meta.PatchOptions{})
		if err != nil {
			return provider.Classify(err)
		}
		if replicas == 0 {
			for range 40 {
				d, err := management.AppsV1().Deployments(ns).Get(call, d.Name, meta.GetOptions{})
				if err != nil {
					return provider.Classify(err)
				}
				if d.Status.Replicas == 0 {
					pods, err := management.CoreV1().Pods(ns).List(call, meta.ListOptions{LabelSelector: "app=" + consumer.ID})
					if err != nil {
						return provider.Classify(err)
					}
					if len(pods.Items) == 0 {
						return nil
					}
				}
				if err := waitLocal(call, 2*time.Second); err != nil {
					return err
				}
			}
			return provider.Transport
		}
		return nil
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 4*time.Minute)
		defer done()
		if err := scale(cleanup, 0); err != nil {
			result = err
			return
		}
		if err := controllerReplicas(cleanup, 0); err != nil {
			result = err
			return
		}
		if err := set(cleanup, true, "TokenFile"); err != nil {
			result = err
			fmt.Println("local StopStart registry restoration requires review")
			return
		}
		if err := controllerReplicas(cleanup, 2); err != nil {
			result = err
		}
	}()
	phase = "disabled-policy-handoff"
	if err := controllerReplicas(ctx, 0); err != nil {
		return err
	}
	if err := set(ctx, false, "StopStart"); err != nil {
		return err
	}
	if err := controllerReplicas(ctx, 2); err != nil {
		return err
	}
	if err := set(ctx, true, "StopStart"); err != nil {
		return err
	}
	phase = "activation"
	// Publication must be fresh under the accepted policy before starting this fixture.
	ready := false
	for range 40 {
		output, err := publish.Read(ctx, management, consumer)
		if err != nil {
			return err
		}
		if output.Annotations[publish.Generation] == expectedGeneration && publish.StoredExpiry(output, values.Registry.Clusters[0], consumer).After(time.Now().Add(8*time.Minute)) {
			ready = true
			break
		}
		if err := waitLocal(ctx, 2*time.Second); err != nil {
			return err
		}
	}
	if !ready {
		return provider.Trust
	}
	if err := scale(ctx, 1); err != nil {
		return err
	}
	seen := map[types.UID]bool{}
	phase = "two-pod-replacements"
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		pods, err := management.CoreV1().Pods(ns).List(ctx, meta.ListOptions{LabelSelector: "app=" + consumer.ID})
		if err != nil {
			return provider.Classify(err)
		}
		for _, p := range pods.Items {
			if p.DeletionTimestamp == nil && len(p.Status.ContainerStatuses) == 1 && p.Status.ContainerStatuses[0].Ready {
				seen[p.UID] = true
			}
		}
		if len(seen) >= 3 {
			break
		}
		if err := waitLocal(ctx, 2*time.Second); err != nil {
			return err
		}
	}
	if len(seen) < 3 {
		fmt.Println("local StopStart Ready Pod identities observed:", len(seen))
		return provider.Trust
	}
	settled := false
	phase = "settled-intent"
	for range 40 {
		s, err := management.CoreV1().ConfigMaps(ns).Get(ctx, "requestor-kube-token-requestor-status", meta.GetOptions{})
		if err != nil {
			return provider.Classify(err)
		}
		var snapshot status.Snapshot
		if json.Unmarshal([]byte(s.Data["state.json"]), &snapshot) != nil {
			return provider.Trust
		}
		entry, ok := snapshot.Consumers[consumer.ID]
		if ok && entry.Intent == nil && !entry.StopLatched && entry.Condition == "Healthy" {
			settled = true
			break
		}
		if err := waitLocal(ctx, 2*time.Second); err != nil {
			return err
		}
	}
	if !settled {
		return provider.Trust
	}
	if err := scale(ctx, 0); err != nil {
		return err
	}
	phase = "manual-suspension"
	if err := waitLocal(ctx, 65*time.Second); err != nil {
		return err
	}
	d, err = management.AppsV1().Deployments(ns).Get(ctx, consumer.CADeployment.Name, meta.GetOptions{})
	if err != nil || d.Spec.Replicas == nil || *d.Spec.Replicas != 0 || d.Status.Replicas != 0 {
		return provider.Trust
	}
	fmt.Println("local StopStart acceptance passed: two real CA Pod replacements; manually suspended consumer stayed stopped")
	return nil
}
