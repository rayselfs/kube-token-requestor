package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/issue"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/publish"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
)

// Fresh Linux runner only. Pauses exactly its kind management API node process;
// leaves child APIs, outputs, grants, replicas and the active worker-hosted CA alone.
func managementOutage(root, path string) (result error) {
	if runtime.GOOS != "linux" || os.Getenv("GITHUB_ACTIONS") != "true" || root != filepath.Join(os.Getenv("RUNNER_TEMP"), "local-acceptance", "kubeconfigs") {
		return provider.Trust
	}
	if host := os.Getenv("DOCKER_HOST"); host != "" && host != "unix:///var/run/docker.sock" {
		return provider.Trust
	}
	if selected := os.Getenv("DOCKER_CONTEXT"); selected != "" && selected != "default" {
		return provider.Trust
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	docker := func(args ...string) ([]byte, error) { return exec.CommandContext(ctx, "docker", args...).Output() }
	out, err := docker("context", "inspect", "default", "--format", "{{.Endpoints.docker.Host}}")
	if err != nil || strings.TrimSpace(string(out)) != "unix:///var/run/docker.sock" {
		return provider.Trust
	}
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
	system, err := management.CoreV1().Namespaces().Get(ctx, "kube-system", meta.GetOptions{})
	if err != nil || string(system.UID) != values.Registry.ManagementUID {
		return provider.Trust
	}
	nodes, err := management.CoreV1().Nodes().List(ctx, meta.ListOptions{})
	if err != nil || len(nodes.Items) != 2 {
		return provider.Trust
	}
	nodeIDs := map[string]string{}
	for _, node := range nodes.Items {
		nodeIDs[node.Name] = string(node.UID)
	}
	if nodeIDs["requestor-management-control-plane"] == "" || nodeIDs["requestor-management-worker"] == "" {
		return provider.Trust
	}
	name := "requestor-kube-token-requestor"
	controller, err := management.AppsV1().Deployments("requestor-test").Get(ctx, name, meta.GetOptions{})
	if err != nil || controller.Spec.Replicas == nil || *controller.Spec.Replicas != 2 || controller.Status.ReadyReplicas != 2 || len(controller.Spec.Template.Spec.Containers) != 1 {
		return provider.Trust
	}
	lease, err := management.CoordinationV1().Leases("requestor-test").Get(ctx, name, meta.GetOptions{})
	if err != nil {
		return provider.Trust
	}
	durable, err := management.CoreV1().ConfigMaps("requestor-test").Get(ctx, name+"-status", meta.GetOptions{})
	if err != nil {
		return provider.Trust
	}
	first := values.Registry.Clusters[0].Consumers[0]
	ca, err := management.AppsV1().Deployments("requestor-test").Get(ctx, first.CADeployment.Name, meta.GetOptions{})
	if err != nil || string(ca.UID) != first.CADeployment.UID || ca.Spec.Replicas == nil || *ca.Spec.Replicas != 1 {
		return provider.Trust
	}
	pods, err := management.CoreV1().Pods("requestor-test").List(ctx, meta.ListOptions{LabelSelector: "app=" + first.ID})
	if err != nil || len(pods.Items) != 1 || pods.Items[0].Spec.NodeName != "requestor-management-worker" || len(pods.Items[0].Status.ContainerStatuses) != 1 || !pods.Items[0].Status.ContainerStatuses[0].Ready || pods.Items[0].Status.ContainerStatuses[0].RestartCount != 0 {
		return provider.Trust
	}
	podUID := pods.Items[0].UID
	hashes := map[string]string{}
	expiries := map[string]time.Time{}
	for _, cluster := range values.Registry.Clusters {
		for _, consumer := range cluster.Consumers {
			secret, err := publish.Read(ctx, management, consumer)
			if err != nil {
				return err
			}
			expires := publish.StoredExpiry(secret, cluster, consumer)
			if expires.Before(time.Now().Add(4 * time.Minute)) {
				return provider.Trust
			}
			hashes[consumer.ID] = credential.Hash(secret.Data["token"])
			expiries[consumer.ID] = expires
		}
	}
	secret, err := publish.Read(ctx, management, first)
	if err != nil {
		return err
	}
	if _, _, err := local(root, "child-a"); err != nil {
		return err
	}
	childConfig, err := clientcmd.LoadFromFile(filepath.Join(root, "child-a"))
	if err != nil || childConfig.Clusters["kind-requestor-child-a"] == nil {
		return provider.Trust
	}
	outside := values.Registry.Clusters[0]
	outside.Endpoint = childConfig.Clusters["kind-requestor-child-a"].Server
	child, err := issue.Client(outside.Endpoint, provider.IssuerCredential{Bearer: string(secret.Data["token"]), CA: secret.Data["ca.crt"]})
	if err != nil {
		return err
	}
	inspect := func() (string, bool, error) {
		out, err := docker("inspect", "--format", "{{.Id}}\n{{json .Config.Labels}}\n{{.State.Paused}}", "requestor-management-control-plane")
		if err != nil {
			return "", false, provider.Transport
		}
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) != 3 || len(lines[0]) != 64 || strings.Trim(lines[0], "0123456789abcdef") != "" {
			return "", false, provider.Trust
		}
		var labels map[string]string
		if json.Unmarshal([]byte(lines[1]), &labels) != nil || labels["io.x-k8s.kind.cluster"] != "requestor-management" || labels["io.x-k8s.kind.role"] != "control-plane" || (lines[2] != "true" && lines[2] != "false") {
			return "", false, provider.Trust
		}
		return lines[0], lines[2] == "true", nil
	}
	id, paused, err := inspect()
	if err != nil || paused {
		return provider.Trust
	}
	if _, err := docker("pause", id); err != nil {
		return provider.Transport
	}
	pauseAt := time.Now()
	restored := false
	defer func() {
		if restored {
			return
		}
		recovery, done := context.WithTimeout(context.Background(), time.Minute)
		defer done()
		out, err := exec.CommandContext(recovery, "docker", "inspect", "--format", "{{.Id}}", "requestor-management-control-plane").Output()
		if err != nil || strings.TrimSpace(string(out)) != id {
			result = provider.Trust
			return
		}
		if exec.CommandContext(recovery, "docker", "unpause", id).Run() != nil {
			result = provider.Transport
		}
	}()
	call, done := context.WithTimeout(ctx, 3*time.Second)
	_, unreachable := management.CoreV1().Namespaces().Get(call, "kube-system", meta.GetOptions{})
	done()
	if unreachable == nil || provider.Classify(unreachable) != provider.Transport {
		return provider.Trust
	}
	if err := issue.ValidateConsumer(ctx, child, outside, first); err != nil {
		return err
	}
	if err := waitLocal(ctx, 90*time.Second); err != nil {
		return err
	}
	if err := issue.ValidateConsumer(ctx, child, outside, first); err != nil {
		return err
	}
	current, paused, err := inspect()
	if err != nil || current != id || !paused {
		return provider.Trust
	}
	if _, err := docker("unpause", id); err != nil {
		return provider.Transport
	}
	restored = true
	pauseSeconds := time.Since(pauseAt).Seconds()
	recoveryAt := time.Now()
	deadline := time.Now().Add(3 * time.Minute)
	for {
		d, err := management.AppsV1().Deployments("requestor-test").Get(ctx, name, meta.GetOptions{})
		ready := err == nil && d.UID == controller.UID && d.Status.ReadyReplicas == 2 && d.Spec.Replicas != nil && *d.Spec.Replicas == 2 && len(d.Spec.Template.Spec.Containers) == 1 && d.Spec.Template.Spec.Containers[0].Image == controller.Spec.Template.Spec.Containers[0].Image
		renewed := 0
		for _, cluster := range values.Registry.Clusters {
			for _, consumer := range cluster.Consumers {
				secret, err := publish.Read(ctx, management, consumer)
				if err != nil {
					ready = false
					continue
				}
				expires := publish.StoredExpiry(secret, cluster, consumer)
				if expires.Before(expiries[consumer.ID]) {
					return provider.Trust
				}
				expiries[consumer.ID] = expires
				if credential.Hash(secret.Data["token"]) != hashes[consumer.ID] {
					renewed++
				}
			}
		}
		if ready && renewed == 3 {
			break
		}
		if time.Now().After(deadline) {
			return provider.Transport
		}
		if err := waitLocal(ctx, time.Second); err != nil {
			return err
		}
	}
	afterLease, err := management.CoordinationV1().Leases("requestor-test").Get(ctx, name, meta.GetOptions{})
	if err != nil || afterLease.UID != lease.UID {
		return provider.Trust
	}
	afterState, err := management.CoreV1().ConfigMaps("requestor-test").Get(ctx, name+"-status", meta.GetOptions{})
	if err != nil || afterState.UID != durable.UID {
		return provider.Trust
	}
	afterNodes, err := management.CoreV1().Nodes().List(ctx, meta.ListOptions{})
	if err != nil || len(afterNodes.Items) != 2 {
		return provider.Trust
	}
	for _, node := range afterNodes.Items {
		if nodeIDs[node.Name] != string(node.UID) {
			return provider.Trust
		}
	}
	pods, err = management.CoreV1().Pods("requestor-test").List(ctx, meta.ListOptions{LabelSelector: "app=" + first.ID})
	if err != nil || len(pods.Items) != 1 || pods.Items[0].UID != podUID || len(pods.Items[0].Status.ContainerStatuses) != 1 || !pods.Items[0].Status.ContainerStatuses[0].Ready || pods.Items[0].Status.ContainerStatuses[0].RestartCount != 0 {
		return provider.Trust
	}
	afterSystem, err := management.CoreV1().Namespaces().Get(ctx, "kube-system", meta.GetOptions{})
	if err != nil || afterSystem.UID != system.UID {
		return provider.Trust
	}
	if err := assert(root, path, false); err != nil {
		return err
	}
	measurement, err := json.Marshal(map[string]any{"pauseSeconds": pauseSeconds, "recoverySeconds": time.Since(recoveryAt).Seconds()})
	if err != nil || pauseSeconds < 90 {
		return provider.Trust
	}
	file, err := os.OpenFile(filepath.Join(filepath.Dir(root), "management-outage-measurement.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return provider.Trust
	}
	if _, err := file.Write(append(measurement, '\n')); err != nil {
		file.Close()
		return provider.Transport
	}
	if file.Close() != nil {
		return provider.Transport
	}
	fmt.Printf("actual management API outage passed: %.1fs node process pause, %.1fs recovery, independent child identity remained valid, same CA Pod and durable state, all outputs renewed without expiry rollback\n", pauseSeconds, time.Since(recoveryAt).Seconds())
	return nil
}
