package oidc

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/issue"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/publish"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// Uses only the uniquely generated API already verified by TestActualKubernetes.
// The broker observes authenticated bound-Pod subjects without exporting their token bytes.
func deployedProjection(t *testing.T, ctx context.Context, client kubernetes.Interface, broker *Broker, root, clusterName, kubeconfig string, c config.Cluster, apiCA []byte) {
	t.Helper()
	image, chart := os.Getenv("REQUESTOR_OIDC_CONTROLLER_IMAGE"), os.Getenv("REQUESTOR_OIDC_CONTROLLER_CHART")
	if !regexp.MustCompile(`^ghcr\.io/rayselfs/kube-token-requestor@sha256:[0-9a-f]{64}$`).MatchString(image) || chart == "" || !filepath.IsAbs(chart) {
		t.Fatal("verified published fixture artifacts required")
	}
	if len(apiCA) == 0 || credential.Hash(apiCA) != c.CASHA256 {
		t.Fatal("synthetic controller public API trust is not pinned")
	}
	digest := strings.Split(image, "@")[1]
	enabled, zero := true, int32(0)
	output, err := client.CoreV1().Secrets("requestor-test").Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "ca-output", Annotations: map[string]string{publish.Owner: "ca-one"}}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"ca.crt": append([]byte(nil), apiCA...), "token": {}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal("synthetic controller output bootstrap failed")
	}
	caDigest := "sha256:aac369dc283927a623deb1af54696efcc722ae79255aa07788422e495bab887d"
	d, err := client.AppsV1().Deployments("requestor-test").Create(ctx, &apps.Deployment{ObjectMeta: meta.ObjectMeta{Name: "ca-fixture"}, Spec: apps.DeploymentSpec{Replicas: &zero, Selector: &meta.LabelSelector{MatchLabels: map[string]string{"app": "ca-fixture"}}, Template: core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: map[string]string{"app": "ca-fixture"}}, Spec: core.PodSpec{Containers: []core.Container{{Name: "ca", Image: "registry.k8s.io/autoscaling/cluster-autoscaler@" + caDigest, Command: []string{"/cluster-autoscaler"}, VolumeMounts: []core.VolumeMount{{Name: "identity", MountPath: "/identity", ReadOnly: true}}}}, Volumes: []core.Volume{{Name: "identity", VolumeSource: core.VolumeSource{Secret: &core.SecretVolumeSource{SecretName: output.Name}}}}}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal("stopped synthetic CA bootstrap failed")
	}
	outsideEndpoint := c.Endpoint
	c.Endpoint = "https://kubernetes.default.svc:443"
	c.Provider.AcceptedMinSeconds = 600
	c.Lifetime.RenewBeforeSeconds = 570
	consumer := &c.Consumers[0]
	consumer.Enabled, consumer.Secret = &enabled, config.Ref{Namespace: output.Namespace, Name: output.Name, UID: string(output.UID)}
	consumer.CADeployment = config.Deployment{Namespace: d.Namespace, Name: d.Name, UID: string(d.UID), ImageDigest: caDigest}
	consumer.ReloadPolicy, consumer.PermissionProfile = "TokenFile", "ca-read-events"
	registry := config.Registry{SchemaVersion: 1, ManagementUID: c.KubeSystemUID, Clusters: []config.Cluster{c}}
	if registry.Validate() != nil {
		t.Fatal("synthetic controller registry invalid")
	}
	values := map[string]any{"registry": registry, "replicaCount": 0, "image": map[string]any{"repository": "ghcr.io/rayselfs/kube-token-requestor", "digest": digest}, "networkPolicy": map[string]any{"enabled": false}, "tolerations": []map[string]string{{"key": "node-role.kubernetes.io/control-plane", "operator": "Exists", "effect": "NoSchedule"}}}
	data, _ := json.Marshal(values)
	valuesPath := filepath.Join(root, "controller-values.json") // non-secret registry and public pins only
	if os.WriteFile(valuesPath, data, 0600) != nil {
		t.Fatal("synthetic controller values export failed")
	}
	command := exec.CommandContext(ctx, "helm", "--kubeconfig", kubeconfig, "--kube-context", "kind-"+clusterName, "install", "projection", chart, "--namespace", "requestor-test", "-f", valuesPath)
	if _, err := command.Output(); err != nil {
		t.Fatal("synthetic stopped chart installation failed")
	}
	name := "projection-kube-token-requestor"
	sa, err := client.CoreV1().ServiceAccounts("requestor-test").Get(ctx, name, meta.GetOptions{})
	if err != nil || broker.BindProjectedSubject("system:serviceaccount:requestor-test:"+name, string(sa.UID)) != nil {
		t.Fatal("synthetic projected subject enrollment failed")
	}
	deployment, err := client.AppsV1().Deployments("requestor-test").Get(ctx, name, meta.GetOptions{})
	if err != nil || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 0 || len(deployment.Spec.Template.Spec.Containers) != 1 || deployment.Spec.Template.Spec.Containers[0].Image != image {
		t.Fatal("stopped published controller fixture invalid")
	}
	projected := false
	for i := range deployment.Spec.Template.Spec.Volumes {
		v := &deployment.Spec.Template.Spec.Volumes[i]
		if v.Name != c.Provider.SubjectTokenVolume || v.Projected == nil {
			continue
		}
		for j := range v.Projected.Sources {
			s := &v.Projected.Sources[j]
			if s.ServiceAccountToken != nil && s.ServiceAccountToken.Audience == c.Provider.SubjectTokenAudience && s.ServiceAccountToken.Path == "token" {
				seconds := int64(600) // accelerated kubelet projection only; shipped chart remains 3600
				s.ServiceAccountToken.ExpirationSeconds = &seconds
				projected = true
			}
		}
	}
	if !projected {
		t.Fatal("chart did not render an explicit subject projection")
	}
	two := int32(2)
	deployment.Spec.Replicas = &two
	if _, err := client.AppsV1().Deployments("requestor-test").Update(ctx, deployment, meta.UpdateOptions{}); err != nil {
		t.Fatal("synthetic projection activation CAS failed")
	}
	// Entire fixture is removed by its outer cluster cleanup. Never uninstall against another API.
	initialPods := map[types.UID]bool{}
	previous, publications := "", 0
	rotated, readySeen := false, false
	publicationAtRotation := 0
	deadline := time.Now().Add(12 * time.Minute)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		pods, err := client.CoreV1().Pods("requestor-test").List(ctx, meta.ListOptions{LabelSelector: "app.kubernetes.io/instance=projection,app.kubernetes.io/name=kube-token-requestor"})
		if err != nil {
			t.Fatal("synthetic controller Pod observation failed")
		}
		ready := 0
		for _, pod := range pods.Items {
			for _, status := range pod.Status.ContainerStatuses {
				if status.RestartCount != 0 {
					t.Fatal("published controller restarted during projection observation")
				}
			}
			for _, condition := range pod.Status.Conditions {
				if condition.Type == core.PodReady && condition.Status == core.ConditionTrue {
					ready++
				}
			}
		}
		if !readySeen && len(pods.Items) == 2 && ready == 2 {
			for _, pod := range pods.Items {
				initialPods[pod.UID] = true
			}
			readySeen = true
		}
		if readySeen {
			if len(pods.Items) != 2 || ready != 2 {
				t.Fatal("published controller lost readiness during projection observation")
			}
			for _, pod := range pods.Items {
				if !initialPods[pod.UID] {
					t.Fatal("published controller Pod replaced during projection observation")
				}
				sample := broker.projectedSample(string(pod.UID))
				if !rotated && sample.Count >= 2 && sample.LatestExpiry > sample.FirstExpiry {
					rotated = true
					publicationAtRotation = publications
				}
			}
		}
		s, err := client.CoreV1().Secrets(output.Namespace).Get(ctx, output.Name, meta.GetOptions{})
		if err != nil || s.UID != output.UID {
			t.Fatal("controller output identity changed")
		}
		if len(s.Data["token"]) > 0 {
			hash := credential.Hash(s.Data["token"])
			if hash != previous {
				cOutside := c
				cOutside.Endpoint = outsideEndpoint
				caClient, err := issue.Client(cOutside.Endpoint, provider.IssuerCredential{Bearer: string(s.Data["token"]), CA: s.Data["ca.crt"]})
				if err != nil || issue.ValidateConsumer(ctx, caClient, cOutside, *consumer) != nil {
					t.Fatal("published controller issued an invalid consumer credential")
				}
				previous = hash
				publications++
			}
		}
		if readySeen && rotated && publications >= 3 && publications >= publicationAtRotation+2 {
			latest, err := client.AppsV1().Deployments(d.Namespace).Get(ctx, d.Name, meta.GetOptions{})
			if err != nil || latest.UID != d.UID || latest.Spec.Replicas == nil || *latest.Spec.Replicas != 0 {
				t.Fatal("stopped CA fixture was modified")
			}
			t.Log("published OAuth controller passed: two unchanged Ready Pods, real bound-Pod projection rotation, valid repeated CA publication; CA stayed stopped")
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("published projection fixture timed out")
		case <-time.After(5 * time.Second):
		}
	}
	t.Fatalf("published projection acceptance failed: ready=%t rotated=%t publications=%d", readySeen, rotated, publications)
}
