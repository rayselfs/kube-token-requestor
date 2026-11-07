package reconcile

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/issue"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/publish"
	"github.com/rayselfs/kube-token-requestor/internal/status"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// Opt-in: only the task-owned loopback kind cluster, never ambient kubeconfig.
func TestGitOpsNativeAPI(t *testing.T) {
	path := os.Getenv("REQUESTOR_GITOPS_TEST_KUBECONFIG")
	if path == "" {
		t.Skip("requires isolated kind fixture")
	}
	raw, err := clientcmd.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if raw.CurrentContext != "kind-requestor-gitops-20261108" {
		t.Fatal("unexpected fixture context")
	}
	cfg, err := clientcmd.NewDefaultClientConfig(*raw, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(cfg.Host)
	if err != nil || u.Scheme != "https" || u.Hostname() != "127.0.0.1" {
		t.Fatal("non-loopback fixture")
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	nodes, err := client.CoreV1().Nodes().List(ctx, meta.ListOptions{})
	if err != nil || len(nodes.Items) != 1 || nodes.Items[0].Name != "requestor-gitops-20261108-control-plane" {
		t.Fatal("fixture ownership mismatch")
	}
	ns, err := client.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{GenerateName: "gitops-test-"}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CoreV1().Namespaces().Delete(context.Background(), ns.Name, meta.DeleteOptions{})
	sa, err := client.CoreV1().ServiceAccounts(ns.Name).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: "gitops"}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := client.CoreV1().Secrets(ns.Name).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "credential-lease"}, Type: core.SecretTypeOpaque}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	issuerSA, err := client.CoreV1().ServiceAccounts(ns.Name).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: "issuer"}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	role := &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: ns.Name}, Rules: []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{"kube-system"}, Verbs: []string{"get"}},
	}}
	if _, err = client.RbacV1().ClusterRoles().Create(ctx, role, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	defer client.RbacV1().ClusterRoles().Delete(context.Background(), ns.Name, meta.DeleteOptions{})
	if _, err = client.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: ns.Name}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: ns.Name}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Namespace: ns.Name, Name: sa.Name}, {Kind: "ServiceAccount", Namespace: ns.Name, Name: issuerSA.Name}}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	defer client.RbacV1().ClusterRoleBindings().Delete(context.Background(), ns.Name, meta.DeleteOptions{})
	if _, err = client.RbacV1().Roles(ns.Name).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "identity"}, Rules: []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, ResourceNames: []string{sa.Name}, Verbs: []string{"get"}},
		{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get", "list", "watch"}},
		{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"probe"}, Verbs: []string{"patch", "update"}},
	}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = client.RbacV1().RoleBindings(ns.Name).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "identity"}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: "identity"}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Namespace: ns.Name, Name: sa.Name}}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = client.RbacV1().Roles(ns.Name).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "issuer"}, Rules: []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, ResourceNames: []string{sa.Name, issuerSA.Name}, Verbs: []string{"get"}},
		{APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, ResourceNames: []string{sa.Name, issuerSA.Name}, Verbs: []string{"create"}},
		{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{lease.Name}, Verbs: []string{"get"}},
	}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = client.RbacV1().RoleBindings(ns.Name).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "issuer"}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: "issuer"}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Namespace: ns.Name, Name: issuerSA.Name}}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	ttl := int64(600)
	initial, err := client.CoreV1().ServiceAccounts(ns.Name).CreateToken(ctx, sa.Name, &auth.TokenRequest{Spec: auth.TokenRequestSpec{ExpirationSeconds: &ttl, BoundObjectRef: &auth.BoundObjectReference{Kind: "Secret", APIVersion: "v1", Name: lease.Name, UID: lease.UID}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := credential.Parse(initial.Status.Token)
	if err != nil {
		t.Fatal(err)
	}
	ca := cfg.CAData
	if len(ca) == 0 {
		t.Fatal("missing fixture CA")
	}
	initialConfig, _ := json.Marshal(map[string]any{"bearerToken": initial.Status.Token, "tlsClientConfig": map[string]any{"insecure": false, "caData": ca}})
	out, err := client.CoreV1().Secrets(ns.Name).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "output", Annotations: map[string]string{publish.Owner: "gitops", publish.Enrollment: "fixture-enrollment"}, Labels: map[string]string{"argocd.argoproj.io/secret-type": "cluster"}}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"name": []byte("fixture"), "server": []byte(cfg.Host), "namespaces": []byte(ns.Name), "project": []byte("fixture"), "clusterResources": []byte("false"), "config": initialConfig}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	state, err := client.CoreV1().ConfigMaps(ns.Name).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: "status"}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	system, err := client.CoreV1().Namespaces().Get(ctx, "kube-system", meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	yes := true
	consumer := config.Consumer{ID: "gitops", Enabled: &yes, Secret: config.Ref{Namespace: ns.Name, Name: out.Name, UID: string(out.UID)}, ServiceAccount: config.ServiceAccount{Name: sa.Name, UID: string(sa.UID)}, PermissionProfile: "gitops-configmap", ReloadPolicy: "ArgoSecret", GitOps: &config.GitOps{Name: "fixture", Project: "fixture", Namespace: ns.Name, ConfigMap: "probe", EnrollmentUID: "fixture-enrollment", BoundSecret: config.Ref{Namespace: ns.Name, Name: lease.Name, UID: string(lease.UID)}}}
	c := config.Cluster{ID: "target", Enabled: &yes, Endpoint: cfg.Host, IdentityNamespace: ns.Name, KubeSystemUID: string(system.UID), CASHA256: credential.Hash(ca), Audiences: claims.Audience, Lifetime: config.Lifetime{RequestedSeconds: 3600, AcceptedMinSeconds: 3500, AcceptedMaxSeconds: 3700, RenewBeforeSeconds: 1800, StopBeforeSeconds: 60, ClockSkewSeconds: 5}, Consumers: []config.Consumer{consumer}}
	e := &Engine{Management: client, Store: &status.Store{Client: client, Namespace: ns.Name, Name: state.Name, UID: string(state.UID)}, Now: time.Now, Current: func(context.Context, string) error { return nil }}
	issuerTTL := int64(7200)
	issuerToken, err := client.CoreV1().ServiceAccounts(ns.Name).CreateToken(ctx, issuerSA.Name, &auth.TokenRequest{Spec: auth.TokenRequestSpec{Audiences: c.Audiences, ExpirationSeconds: &issuerTTL}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	issuerClient, err := issue.Client(c.Endpoint, provider.IssuerCredential{Bearer: issuerToken.Status.Token, CA: ca})
	if err != nil {
		t.Fatal(err)
	}
	c.ExpectedIssuer = config.Principal{Username: "system:serviceaccount:" + ns.Name + ":" + issuerSA.Name, Groups: []string{"system:serviceaccounts", "system:serviceaccounts:" + ns.Name, "system:authenticated"}}
	c.Provider = config.Provider{Type: "SecretIssuer", ServiceAccount: &config.ServiceAccount{Name: issuerSA.Name, UID: string(issuerSA.UID)}, Renewal: &config.Lifetime{}}
	if err = issue.Issuer(ctx, issuerClient, c); err != nil {
		t.Fatal("issuer RBAC", err)
	}

	err = e.consumer(ctx, c, consumer, "fixture", status.Consumer{}, issuerClient, provider.IssuerCredential{CA: ca}, nil, true)
	if err != nil {
		t.Fatal("native rotation", err)
	}
	fresh, err := client.CoreV1().Secrets(ns.Name).Get(ctx, out.Name, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	freshMaterial, err := publish.Material(fresh, c, consumer)
	if err != nil {
		t.Fatal(err)
	}
	if freshMaterial.Bearer == initial.Status.Token || !publish.StoredExpiry(fresh, c, consumer).After(initial.Status.ExpirationTimestamp.Time) {
		t.Fatal("rotation not committed")
	}
	snapshot, err := e.Store.Read(ctx)
	if err != nil || snapshot.Consumers["gitops"].Condition != "CredentialPublished" {
		t.Fatal("publication status")
	}

	// An excessive target grant must latch failure, not mint another token.
	role.Rules = append(role.Rules, rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}})
	current, err := client.RbacV1().ClusterRoles().Get(ctx, role.Name, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	current.Rules = role.Rules
	if _, err = client.RbacV1().ClusterRoles().Update(ctx, current, meta.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	err = e.consumer(ctx, c, consumer, "fixture", snapshot.Consumers["gitops"], issuerClient, provider.IssuerCredential{CA: ca}, nil, true)
	if err == nil {
		t.Fatal("excess privilege accepted")
	}
	after, _ := client.CoreV1().Secrets(ns.Name).Get(ctx, out.Name, meta.GetOptions{})
	if !strings.EqualFold(after.ResourceVersion, fresh.ResourceVersion) {
		t.Fatal("unsafe publication")
	}
	// Retirement revokes the exact identity, not just its Secret delivery.
	if err = client.CoreV1().Secrets(ns.Name).Delete(ctx, lease.Name, meta.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		review, reviewErr := client.AuthenticationV1().TokenReviews().Create(ctx, &auth.TokenReview{Spec: auth.TokenReviewSpec{Token: freshMaterial.Bearer}}, meta.CreateOptions{})
		if reviewErr != nil {
			t.Fatal("retirement TokenReview failed")
		}
		if !review.Status.Authenticated {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("retired identity still authenticates")
		}
		time.Sleep(time.Second)
	}
	replacement, err := client.CoreV1().Secrets(ns.Name).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: lease.Name}, Type: core.SecretTypeOpaque}, meta.CreateOptions{})
	if err != nil || replacement.UID == lease.UID {
		t.Fatal("replacement lease fixture failed")
	}
	if _, err = issue.Request(ctx, issuerClient, c, consumer, ca, time.Now()); err != provider.Trust {
		t.Fatal("changed lease UID accepted")
	}
	snapshot, err = e.Store.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.consumer(ctx, c, consumer, "fixture", snapshot.Consumers["gitops"], issuerClient, provider.IssuerCredential{CA: ca}, nil, true); err == nil {
		t.Fatal("retired identity silently rebound")
	}
	after, err = client.CoreV1().Secrets(ns.Name).Get(ctx, out.Name, meta.GetOptions{})
	if err != nil || after.ResourceVersion != fresh.ResourceVersion {
		t.Fatal("retirement unexpectedly republished")
	}
	if err = client.CoreV1().Secrets(ns.Name).Delete(ctx, out.Name, meta.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err = e.consumer(ctx, c, consumer, "fixture", snapshot.Consumers["gitops"], issuerClient, provider.IssuerCredential{CA: ca}, nil, true); err == nil {
		t.Fatal("missing retired output accepted")
	}
	t.Log("native lease retirement, invalidated bearer, no UID rebind and missing-output rejection passed")
	t.Log("native TokenRequest, identity/RBAC checks, Secret CAS publication and excessive-grant rejection passed")
}
