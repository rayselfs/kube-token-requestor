package capacity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/publish"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
)

func (f *fixture) installController(t *testing.T, ctx context.Context, clusters []config.Cluster, tokens [][]byte, public []byte) config.Registry {
	t.Helper()
	f.guardNamespace(t, ctx)
	image, chart := os.Getenv("REQUESTOR_CAPACITY_CONTROLLER_IMAGE"), os.Getenv("REQUESTOR_CAPACITY_CONTROLLER_CHART")
	if !regexp.MustCompile(`^ghcr\.io/rayselfs/kube-token-requestor@sha256:[0-9a-f]{64}$`).MatchString(image) || !filepath.IsAbs(chart) {
		t.Fatal("capacity requires verified published artifacts")
	}
	system, err := f.client.CoreV1().Namespaces().Get(ctx, "kube-system", meta.GetOptions{})
	if err != nil {
		t.Fatal("management identity read failed")
	}
	registry := config.Registry{SchemaVersion: 1, ManagementUID: string(system.UID), Clusters: clusters}
	_, err = f.client.CoreV1().ServiceAccounts(f.namespace).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: "ca-management"}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal("isolated CA management account failed")
	}
	_, err = f.client.RbacV1().Roles(f.namespace).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "ca-management"}, Rules: []rbac.PolicyRule{{APIGroups: []string{"cluster.x-k8s.io", "exp.cluster.x-k8s.io"}, Resources: []string{"clusters", "machines", "machinesets", "machinedeployments", "machinepools"}, Verbs: []string{"get", "list", "watch"}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal("isolated read-only CAPI grant failed")
	}
	bind(t, ctx, f.client, f.namespace, "ca-management", "Role", []string{"ca-management"})
	for i := range registry.Clusters {
		c := &registry.Clusters[i]
		source, err := f.client.CoreV1().Secrets(f.namespace).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: c.ID + "-issuer"}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"ca.crt": public, "token": tokens[i]}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal("restricted issuer source enrollment failed")
		}
		c.Provider.Secret = &config.Ref{Namespace: f.namespace, Name: source.Name, UID: string(source.UID)}
		for j := range c.Consumers {
			consumer := &c.Consumers[j]
			output, err := f.client.CoreV1().Secrets(f.namespace).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: consumer.ID, Annotations: map[string]string{publish.Owner: consumer.ID}}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"ca.crt": public, "token": {}}}, meta.CreateOptions{})
			if err != nil {
				t.Fatal("candidate output bootstrap failed")
			}
			consumer.Secret = config.Ref{Namespace: f.namespace, Name: output.Name, UID: string(output.UID)}
			kubeconfig := fmt.Sprintf("apiVersion: v1\nkind: Config\nclusters:\n- name: child\n  cluster:\n    server: %s\n    certificate-authority: /identity/ca.crt\nusers:\n- name: ca\n  user:\n    tokenFile: /identity/token\ncontexts:\n- name: child\n  context:\n    cluster: child\n    user: ca\ncurrent-context: child\n", c.Endpoint)
			_, err = f.client.CoreV1().ConfigMaps(f.namespace).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: consumer.ID + "-config"}, Data: map[string]string{"child.kubeconfig": kubeconfig}}, meta.CreateOptions{})
			if err != nil {
				t.Fatal("credential-free CA config failed")
			}
			zero := int32(0)
			d := &apps.Deployment{ObjectMeta: meta.ObjectMeta{Name: consumer.ID}, Spec: apps.DeploymentSpec{Replicas: &zero, Selector: &meta.LabelSelector{MatchLabels: map[string]string{"capacity-ca": consumer.ID}}, Template: core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: map[string]string{"capacity-ca": consumer.ID, "capacity-fixture": f.name}}, Spec: core.PodSpec{ServiceAccountName: "ca-management", Containers: []core.Container{{Name: "ca", Image: "registry.k8s.io/autoscaling/cluster-autoscaler@" + caDigest, Command: []string{"/cluster-autoscaler"}, Args: []string{"--cloud-provider=clusterapi", "--clusterapi-cloud-config-authoritative", "--kubeconfig=/config/child.kubeconfig", "--node-group-auto-discovery=clusterapi:namespace=" + f.namespace + ",clusterName=" + c.ID, "--scale-down-enabled=false", "--leader-elect=false", "--write-status-configmap=false", "--scan-interval=10s", "--v=2"}, Env: []core.EnvVar{{Name: "CAPI_VERSION", Value: "v1beta1"}}, Resources: resources("25m", "64Mi"), VolumeMounts: []core.VolumeMount{{Name: "identity", MountPath: "/identity", ReadOnly: true}, {Name: "config", MountPath: "/config", ReadOnly: true}}}}, Volumes: []core.Volume{{Name: "identity", VolumeSource: core.VolumeSource{Secret: &core.SecretVolumeSource{SecretName: output.Name}}}, {Name: "config", VolumeSource: core.VolumeSource{ConfigMap: &core.ConfigMapVolumeSource{LocalObjectReference: core.LocalObjectReference{Name: consumer.ID + "-config"}}}}}}}}}
			created, err := f.client.AppsV1().Deployments(f.namespace).Create(ctx, d, meta.CreateOptions{})
			if err != nil {
				t.Fatal("stopped actual CA creation failed")
			}
			consumer.CADeployment = config.Deployment{Namespace: f.namespace, Name: created.Name, UID: string(created.UID), ImageDigest: caDigest}
		}
	}
	if registry.Validate() != nil {
		t.Fatal("actual capacity enrollment invalid")
	}
	values := map[string]any{"registry": registry, "replicaCount": 2, "image": map[string]any{"repository": "ghcr.io/rayselfs/kube-token-requestor", "digest": strings.Split(image, "@")[1]}, "networkPolicy": map[string]any{"enabled": false}, "tolerations": []map[string]string{{"key": "node-role.kubernetes.io/control-plane", "operator": "Exists", "effect": "NoSchedule"}}}
	data, err := json.Marshal(values)
	path := filepath.Join(f.root, "values.json")
	if err != nil || os.WriteFile(path, data, 0600) != nil {
		t.Fatal("non-secret capacity registry export failed")
	}
	cmd := exec.CommandContext(ctx, "helm", "--kubeconfig", f.kubeconfig, "--kube-context", "kind-"+f.name, "install", "capacity", chart, "--namespace", f.namespace, "-f", path, "--wait", "--timeout", "4m")
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if cmd.Run() != nil {
		t.Fatal("published capacity controller install failed")
	}
	return registry
}
func (f *fixture) activateCAs(t *testing.T, ctx context.Context, registry config.Registry) {
	t.Helper()
	f.guardNamespace(t, ctx)
	// Fixture-only CRDs, in this newly generated cluster, never a shared/operator cluster.
	command := exec.CommandContext(ctx, "kubectl", "--kubeconfig", f.kubeconfig, "--context", "kind-"+f.name, "apply", "-f", "../fixtures/capi-crds.json")
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if command.Run() != nil {
		t.Fatal("isolated empty CAPI schema creation failed")
	}
	for _, c := range registry.Clusters {
		for _, consumer := range c.Consumers {
			err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				d, err := f.client.AppsV1().Deployments(f.namespace).Get(ctx, consumer.CADeployment.Name, meta.GetOptions{})
				if err != nil {
					return err
				}
				if string(d.UID) != consumer.CADeployment.UID || d.Spec.Replicas == nil || *d.Spec.Replicas != 0 || len(d.Spec.Template.Spec.Containers) != 1 || d.Spec.Template.Spec.Containers[0].Image != "registry.k8s.io/autoscaling/cluster-autoscaler@"+caDigest {
					t.Fatal("actual capacity CA activation target changed")
				}
				one := int32(1)
				d.Spec.Replicas = &one
				_, err = f.client.AppsV1().Deployments(f.namespace).Update(ctx, d, meta.UpdateOptions{})
				return err
			})
			if err != nil {
				t.Fatal("guarded capacity CA activation failed")
			}
		}
	}
	deadline := time.NewTimer(4 * time.Minute)
	defer deadline.Stop()
	for {
		pods, err := f.client.CoreV1().Pods(f.namespace).List(ctx, meta.ListOptions{LabelSelector: "capacity-fixture=" + f.name})
		ready := 0
		if err == nil {
			for _, pod := range pods.Items {
				for _, condition := range pod.Status.Conditions {
					if condition.Type == core.PodReady && condition.Status == core.ConditionTrue {
						ready++
					}
				}
			}
		}
		if err == nil && len(pods.Items) == len(registry.Clusters)*3 && ready == len(pods.Items) {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("capacity CA readiness cancelled")
		case <-deadline.C:
			t.Fatal("all actual capacity CAs did not become Ready")
		case <-time.After(time.Second):
		}
	}
}
