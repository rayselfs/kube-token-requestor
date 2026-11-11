// The local harness creates synthetic resources only in explicitly named loopback kind clusters.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/issue"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/publish"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "local acceptance failed:", provider.Classify(err))
		os.Exit(1)
	}
}
func run() error {
	root := flag.String("kubeconfigs", "", "task-local kind kubeconfig directory")
	out := flag.String("values", "", "non-secret generated Helm values path")
	action := flag.String("action", "bootstrap", "bootstrap or assert")
	duration := flag.Duration("duration", 13*time.Minute, "local rotation observation duration")
	manifest := flag.String("manifest", "", "verified public release manifest for natural observation")
	evidence := flag.String("evidence", "", "checkpoint path outside source checkout")
	digest := flag.String("ca-digest", "sha256:"+strings.Repeat("1", 64), "synthetic stopped CA image digest")
	flag.Parse()
	if *root == "" || *out == "" {
		return provider.Trust
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if *action == "observe-natural" {
		return observeNatural(*root, *out, *manifest, *evidence, *duration)
	}
	if *action == "observe" {
		return observe(*root, *out, *duration)
	}
	if *action == "revoke-issuer" {
		return revokeIssuer(*root, *out)
	}
	if *action == "partition" {
		return partition(*root, *out)
	}
	if *action == "faults" {
		return faults(*root, *out)
	}
	if *action == "management-outage" {
		return managementOutage(*root, *out)
	}
	if *action == "failover" {
		return failover(*root, *out)
	}
	if *action == "stop-start" {
		return stopStart(*root, *out)
	}
	if *action == "configure-ca" {
		return configureCA(*root, *out, *digest)
	}
	if *action == "assert" {
		return assert(*root, *out, true)
	}
	if *action == "rights" {
		return assert(*root, *out, false)
	}
	if *action != "bootstrap" {
		return provider.Trust
	}
	management, _, err := local(*root, "management")
	if err != nil {
		return err
	}
	_, err = management.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: "requestor-test"}}, meta.CreateOptions{})
	if err != nil {
		return err
	}
	uid, err := management.CoreV1().Namespaces().Get(ctx, "kube-system", meta.GetOptions{})
	if err != nil {
		return err
	}
	registry := config.Registry{SchemaVersion: 1, ManagementUID: string(uid.UID), Clusters: []config.Cluster{}}
	for index, name := range []string{"child-a", "child-b"} {
		client, trust, err := local(*root, name)
		if err != nil {
			return err
		}
		ns := "requestor-identity"
		_, err = client.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: ns}}, meta.CreateOptions{})
		if err != nil {
			return err
		}
		names := []string{"ca-one"}
		if index == 0 {
			names = append(names, "ca-two")
		}
		issuer, err := client.CoreV1().ServiceAccounts(ns).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: "issuer"}}, meta.CreateOptions{})
		if err != nil {
			return err
		}
		accounts := map[string]core.ServiceAccount{}
		for _, name := range names {
			sa, err := client.CoreV1().ServiceAccounts(ns).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: name}}, meta.CreateOptions{})
			if err != nil {
				return err
			}
			accounts[name] = *sa
		}
		_, err = client.RbacV1().Roles(ns).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "issuer"}, Rules: []rbac.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, ResourceNames: names, Verbs: []string{"create"}},
			{APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, ResourceNames: append(append([]string{}, names...), "issuer"), Verbs: []string{"get"}},
		}}, meta.CreateOptions{})
		if err != nil {
			return err
		}
		if err := binding(ctx, client, ns, "issuer", rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: "issuer"}, []string{"issuer"}, false); err != nil {
			return err
		}
		identityRules := []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{"kube-system"}, Verbs: []string{"get"}},
			{APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"selfsubjectreviews"}, Verbs: []string{"create"}},
			{APIGroups: []string{"authorization.k8s.io"}, Resources: []string{"selfsubjectaccessreviews", "selfsubjectrulesreviews"}, Verbs: []string{"create"}}}
		_, err = client.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: "requestor-identity"}, Rules: identityRules}, meta.CreateOptions{})
		if err != nil {
			return err
		}
		if err := binding(ctx, client, ns, "requestor-identity", rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: "requestor-identity"}, append(append([]string{}, names...), "issuer"), true); err != nil {
			return err
		}
		_, err = client.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: "ca-read-events"}, Rules: []rbac.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"nodes", "pods", "services", "namespaces", "endpoints", "persistentvolumes", "persistentvolumeclaims", "replicationcontrollers"}, Verbs: []string{"get", "list", "watch"}},
			{APIGroups: []string{"apps"}, Resources: []string{"daemonsets", "replicasets", "statefulsets"}, Verbs: []string{"get", "list", "watch"}},
			{APIGroups: []string{"batch"}, Resources: []string{"jobs"}, Verbs: []string{"get", "list", "watch"}},
			{APIGroups: []string{"resource.k8s.io"}, Resources: []string{"deviceclasses", "resourceclaims", "resourceslices"}, Verbs: []string{"get", "list", "watch"}},
			{APIGroups: []string{"policy"}, Resources: []string{"poddisruptionbudgets"}, Verbs: []string{"get", "list", "watch"}},
			{APIGroups: []string{"storage.k8s.io"}, Resources: []string{"storageclasses", "csinodes", "csidrivers", "volumeattachments", "csistoragecapacities"}, Verbs: []string{"get", "list", "watch"}},
			{APIGroups: []string{""}, Resources: []string{"events"}, Verbs: []string{"create", "patch"}},
			{APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, ResourceNames: names, Verbs: []string{"get"}},
		}}, meta.CreateOptions{})
		if err != nil {
			return err
		}
		if err := binding(ctx, client, ns, "ca-read-events", rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: "ca-read-events"}, names, true); err != nil {
			return err
		}
		tokenObject, err := client.CoreV1().Secrets(ns).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "issuer-token", Annotations: map[string]string{core.ServiceAccountNameKey: "issuer"}}, Type: core.SecretTypeServiceAccountToken}, meta.CreateOptions{})
		if err != nil {
			return err
		}
		for len(tokenObject.Data["token"]) == 0 {
			select {
			case <-ctx.Done():
				return provider.Transport
			case <-time.After(time.Second):
			}
			tokenObject, err = client.CoreV1().Secrets(ns).Get(ctx, "issuer-token", meta.GetOptions{})
			if err != nil {
				return err
			}
		}
		system, err := client.CoreV1().Namespaces().Get(ctx, "kube-system", meta.GetOptions{})
		if err != nil {
			return err
		}
		enabled := true
		long := true
		issuerSecret, err := management.CoreV1().Secrets("requestor-test").Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: name + "-issuer", Annotations: map[string]string{"token-requestor.io/rotated-at": time.Now().UTC().Format(time.RFC3339)}}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"ca.crt": trust, "token": tokenObject.Data["token"]}}, meta.CreateOptions{})
		if err != nil {
			return err
		}
		endpoint := "https://requestor-" + name + "-control-plane:6443"
		c := config.Cluster{ID: name, Enabled: &enabled, Endpoint: endpoint, KubeSystemUID: string(system.UID), CASHA256: credential.Hash(trust), IdentityNamespace: ns, Audiences: []string{"https://kubernetes.default.svc.cluster.local"}, ExpectedIssuer: config.Principal{Username: "system:serviceaccount:" + ns + ":issuer", Groups: []string{"system:serviceaccounts", "system:serviceaccounts:" + ns, "system:authenticated"}}, Provider: config.Provider{Type: "SecretIssuer", ServiceAccount: &config.ServiceAccount{Name: "issuer", UID: string(issuer.UID)}, Secret: &config.Ref{Namespace: "requestor-test", Name: name + "-issuer", UID: string(issuerSecret.UID)}, LongLived: &long, RotationPeriodSeconds: 90 * 86400}, Lifetime: config.Lifetime{RequestedSeconds: 600, AcceptedMinSeconds: 590, AcceptedMaxSeconds: 610, RenewBeforeSeconds: 300, StopBeforeSeconds: 60, ClockSkewSeconds: 5}, Consumers: []config.Consumer{}}
		for _, account := range names {
			id := name + "-" + account
			replicas := int32(0)
			dep, err := management.AppsV1().Deployments("requestor-test").Create(ctx, &apps.Deployment{ObjectMeta: meta.ObjectMeta{Name: id}, Spec: apps.DeploymentSpec{Replicas: &replicas, Selector: &meta.LabelSelector{MatchLabels: map[string]string{"app": id}}, Template: core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: map[string]string{"app": id}}, Spec: core.PodSpec{Containers: []core.Container{{Name: "ca", Image: "registry.k8s.io/autoscaling/cluster-autoscaler@" + *digest}}}}}}, meta.CreateOptions{})
			if err != nil {
				return err
			}
			secret, err := management.CoreV1().Secrets("requestor-test").Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: id, Annotations: map[string]string{publish.Owner: id}}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"ca.crt": trust, "token": {}}}, meta.CreateOptions{})
			if err != nil {
				return err
			}
			c.Consumers = append(c.Consumers, config.Consumer{ID: id, Enabled: &enabled, ServiceAccount: config.ServiceAccount{Name: account, UID: string(accounts[account].UID)}, Secret: config.Ref{Namespace: "requestor-test", Name: id, UID: string(secret.UID)}, CADeployment: config.Deployment{Namespace: "requestor-test", Name: id, UID: string(dep.UID), ImageDigest: *digest}, ReloadPolicy: "TokenFile", PermissionProfile: "ca-read-events"})
		}
		registry.Clusters = append(registry.Clusters, c)
	}
	if registry.Validate() != nil {
		return provider.Trust
	}
	data, err := json.MarshalIndent(map[string]any{"registry": registry, "networkPolicy": map[string]any{"enabled": false}, "tolerations": []map[string]string{{"key": "node-role.kubernetes.io/control-plane", "operator": "Exists", "effect": "NoSchedule"}}}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, data, 0600); err != nil {
		return err
	}
	fmt.Println("synthetic bootstrap complete: two children, three stopped CA consumers; credentials remain in local API Secrets")
	return nil
}
func local(root, role string) (kubernetes.Interface, []byte, error) {
	name := "requestor-" + role
	cfg, err := clientcmd.LoadFromFile(filepath.Join(root, role))
	if err != nil {
		return nil, nil, provider.Trust
	}
	selected := cfg.Contexts["kind-"+name]
	if selected == nil || selected.Cluster != "kind-"+name || selected.AuthInfo != "kind-"+name {
		return nil, nil, provider.Trust
	}
	cluster, auth := cfg.Clusters[selected.Cluster], cfg.AuthInfos[selected.AuthInfo]
	if cluster == nil || auth == nil || auth.Exec != nil || auth.AuthProvider != nil || cluster.InsecureSkipTLSVerify || cluster.ProxyURL != "" {
		return nil, nil, provider.Trust
	}
	parsed, err := url.Parse(cluster.Server)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, nil, provider.Trust
	}
	ip := net.ParseIP(parsed.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return nil, nil, provider.Trust
	}
	c, err := kubernetes.NewForConfig(&rest.Config{Host: cluster.Server, TLSClientConfig: rest.TLSClientConfig{CAData: cluster.CertificateAuthorityData, CertData: auth.ClientCertificateData, KeyData: auth.ClientKeyData}, Timeout: 10 * time.Second})
	if err != nil {
		return nil, nil, provider.Trust
	}
	nodes, err := c.CoreV1().Nodes().List(context.Background(), meta.ListOptions{})
	if err != nil {
		return nil, nil, provider.Trust
	}
	if len(nodes.Items) == 0 {
		return nil, nil, provider.Trust
	}
	for _, node := range nodes.Items {
		if !strings.HasPrefix(node.Name, name+"-") {
			return nil, nil, provider.Trust
		}
	}
	return c, cluster.CertificateAuthorityData, nil
}

func binding(ctx context.Context, client kubernetes.Interface, ns, name string, ref rbac.RoleRef, names []string, cluster bool) error {
	subjects := []rbac.Subject{}
	for _, account := range names {
		subjects = append(subjects, rbac.Subject{Kind: "ServiceAccount", Namespace: ns, Name: account})
	}
	if cluster {
		_, err := client.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: name}, RoleRef: ref, Subjects: subjects}, meta.CreateOptions{})
		return err
	}
	_, err := client.RbacV1().RoleBindings(ns).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: name}, RoleRef: ref, Subjects: subjects}, meta.CreateOptions{})
	return err
}

func assert(root, path string, requireStopped bool) error {
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
	management, _, err := local(root, "management")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	identity, err := management.CoreV1().Namespaces().Get(ctx, "kube-system", meta.GetOptions{})
	if err != nil || string(identity.UID) != values.Registry.ManagementUID {
		return provider.Trust
	}
	distinct := map[string]bool{}
	count := 0
	for _, cluster := range values.Registry.Clusters {
		if _, _, err := local(root, cluster.ID); err != nil {
			return err
		}
		cfg, err := clientcmd.LoadFromFile(filepath.Join(root, cluster.ID))
		if err != nil {
			return provider.Trust
		}
		endpoint := cfg.Clusters["kind-requestor-"+cluster.ID].Server
		target := cluster
		target.Endpoint = endpoint
		identity, err := (provider.SecretIssuer{Management: management, Now: time.Now}).Acquire(ctx, target)
		if err != nil {
			return err
		}
		issuer, err := issue.Client(endpoint, identity)
		if err != nil {
			return err
		}
		if err := issue.Issuer(ctx, issuer, target); err != nil {
			return err
		}
		for _, consumer := range cluster.Consumers {
			output, err := publish.Read(ctx, management, consumer)
			if err != nil {
				return err
			}
			expires := publish.StoredExpiry(output, cluster, consumer)
			if !expires.After(time.Now().Add(time.Minute)) {
				return provider.Trust
			}
			hash := credential.Hash(output.Data["token"])
			if distinct[hash] {
				return provider.Trust
			}
			distinct[hash] = true
			restricted, err := issue.Client(endpoint, provider.IssuerCredential{Bearer: string(output.Data["token"]), CA: output.Data["ca.crt"]})
			if err != nil {
				return err
			}
			if err := issue.ValidateConsumer(ctx, restricted, target, consumer); err != nil {
				return err
			}
			deployment, err := management.AppsV1().Deployments(consumer.CADeployment.Namespace).Get(ctx, consumer.CADeployment.Name, meta.GetOptions{})
			if err != nil || string(deployment.UID) != consumer.CADeployment.UID || deployment.Spec.Replicas == nil || (requireStopped && *deployment.Spec.Replicas != 0) {
				return provider.Trust
			}
			count++
		}
	}
	fmt.Printf("real local API acceptance passed: %d distinct CA tokens, issuer/consumer identity and effective rights checked; stoppedRequired=%t\n", count, requireStopped)
	return nil
}

func configureCA(root, path, digest string) error {
	management, _, err := local(root, "management")
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return provider.Trust
	}
	var values map[string]json.RawMessage
	if json.Unmarshal(data, &values) != nil {
		return provider.Trust
	}
	var registry config.Registry
	if json.Unmarshal(values["registry"], &registry) != nil || registry.Validate() != nil {
		return provider.Trust
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	identity, err := management.CoreV1().Namespaces().Get(ctx, "kube-system", meta.GetOptions{})
	if err != nil || string(identity.UID) != registry.ManagementUID {
		return provider.Trust
	}
	// Require the shared controller to be stopped before changing synthetic fixture bindings.
	controller, err := management.AppsV1().Deployments("requestor-test").Get(ctx, "requestor-kube-token-requestor", meta.GetOptions{})
	if err != nil || controller.Spec.Replicas == nil || *controller.Spec.Replicas != 0 || controller.Status.Replicas != 0 {
		return provider.Trust
	}
	_, err = management.CoreV1().ServiceAccounts("requestor-test").Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: "ca-management"}}, meta.CreateOptions{})
	if err != nil {
		return err
	}
	_, err = management.RbacV1().Roles("requestor-test").Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "ca-management"}, Rules: []rbac.PolicyRule{{APIGroups: []string{"cluster.x-k8s.io", "exp.cluster.x-k8s.io"}, Resources: []string{"clusters", "machines", "machinesets", "machinedeployments", "machinepools"}, Verbs: []string{"get", "list", "watch"}}}}, meta.CreateOptions{})
	if err != nil {
		return err
	}
	if err := binding(ctx, management, "requestor-test", "ca-management", rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: "ca-management"}, []string{"ca-management"}, false); err != nil {
		return err
	}
	for i := range registry.Clusters {
		c := &registry.Clusters[i]
		c.Lifetime.RenewBeforeSeconds = 570
		for j := range c.Consumers {
			consumer := &c.Consumers[j]
			consumer.CADeployment.ImageDigest = digest
			object, err := management.AppsV1().Deployments(consumer.CADeployment.Namespace).Get(ctx, consumer.CADeployment.Name, meta.GetOptions{})
			if err != nil || string(object.UID) != consumer.CADeployment.UID || object.Spec.Replicas == nil || *object.Spec.Replicas != 0 {
				return provider.Trust
			}
			kubeconfig := fmt.Sprintf("apiVersion: v1\nkind: Config\nclusters:\n- name: child\n  cluster:\n    server: %s\n    certificate-authority: /identity/ca.crt\nusers:\n- name: ca\n  user:\n    tokenFile: /identity/token\ncontexts:\n- name: child\n  context:\n    cluster: child\n    user: ca\ncurrent-context: child\n", c.Endpoint)
			_, err = management.CoreV1().ConfigMaps("requestor-test").Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: consumer.ID + "-config"}, Data: map[string]string{"child.kubeconfig": kubeconfig}}, meta.CreateOptions{})
			if err != nil {
				return err
			}
			object.Spec.Template.Spec.ServiceAccountName = "ca-management"
			object.Spec.Template.Spec.Containers = []core.Container{{Name: "ca", Image: "registry.k8s.io/autoscaling/cluster-autoscaler@" + digest, Command: []string{"/cluster-autoscaler"}, Args: []string{"--cloud-provider=clusterapi", "--clusterapi-cloud-config-authoritative", "--kubeconfig=/config/child.kubeconfig", "--node-group-auto-discovery=clusterapi:namespace=requestor-test,clusterName=" + c.ID, "--scale-down-enabled=false", "--leader-elect=false", "--write-status-configmap=false", "--scan-interval=10s", "--v=2"}, Env: []core.EnvVar{{Name: "CAPI_VERSION", Value: "v1beta1"}}, VolumeMounts: []core.VolumeMount{{Name: "identity", MountPath: "/identity", ReadOnly: true}, {Name: "config", MountPath: "/config", ReadOnly: true}}}}
			object.Spec.Template.Spec.Volumes = []core.Volume{{Name: "identity", VolumeSource: core.VolumeSource{Secret: &core.SecretVolumeSource{SecretName: consumer.Secret.Name}}}, {Name: "config", VolumeSource: core.VolumeSource{ConfigMap: &core.ConfigMapVolumeSource{LocalObjectReference: core.LocalObjectReference{Name: consumer.ID + "-config"}}}}}
			if _, err = management.AppsV1().Deployments("requestor-test").Update(ctx, object, meta.UpdateOptions{}); err != nil {
				return err
			}
		}
	}
	if registry.Validate() != nil {
		return provider.Trust
	}
	values["registry"], _ = json.Marshal(registry)
	data, _ = json.MarshalIndent(values, "", "  ")
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	fmt.Println("local actual-CA fixtures configured while stopped; read-only CAPI management identity, no node pools or scaling grants")
	return nil
}
