package capacity

import (
	"context"
	"fmt"
	"testing"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const identityNS = "requestor-identity"

func ensureNamespace(t *testing.T, ctx context.Context, client kubernetes.Interface, name string) *core.Namespace {
	t.Helper()
	object, err := client.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: name}}, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		object, err = client.CoreV1().Namespaces().Get(ctx, name, meta.GetOptions{})
	}
	if err != nil {
		t.Fatal("synthetic namespace enrollment failed")
	}
	return object
}
func bind(t *testing.T, ctx context.Context, client kubernetes.Interface, namespace, name, kind string, accounts []string) {
	t.Helper()
	subjects := []rbac.Subject{}
	for _, account := range accounts {
		subjects = append(subjects, rbac.Subject{Kind: "ServiceAccount", Name: account, Namespace: namespace})
	}
	ref := rbac.RoleRef{APIGroup: rbac.GroupName, Kind: kind, Name: name}
	var err error
	if kind == "ClusterRole" {
		_, err = client.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: name}, RoleRef: ref, Subjects: subjects}, meta.CreateOptions{})
	} else {
		_, err = client.RbacV1().RoleBindings(namespace).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: name}, RoleRef: ref, Subjects: subjects}, meta.CreateOptions{})
	}
	if err != nil {
		t.Fatal("synthetic named binding failed")
	}
}
func (c *child) enroll(t *testing.T, ctx context.Context, publicCA []byte) (config.Cluster, []byte) {
	t.Helper()
	system := ensureNamespace(t, ctx, c.client, "kube-system")
	ensureNamespace(t, ctx, c.client, identityNS)
	accounts := map[string]config.ServiceAccount{}
	names := []string{"ca-0", "ca-1", "ca-2"}
	for _, name := range append(append([]string{}, names...), "issuer") {
		sa, err := c.client.CoreV1().ServiceAccounts(identityNS).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: name}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal("synthetic account creation failed")
		}
		accounts[name] = config.ServiceAccount{Name: name, UID: string(sa.UID)}
	}
	_, err := c.client.RbacV1().Roles(identityNS).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "issuer"}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, ResourceNames: names, Verbs: []string{"create"}}, {APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, ResourceNames: append(append([]string{}, names...), "issuer"), Verbs: []string{"get"}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal("synthetic named issuer grant failed")
	}
	bind(t, ctx, c.client, identityNS, "issuer", "Role", []string{"issuer"})
	identity := []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{"kube-system"}, Verbs: []string{"get"}}, {APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"selfsubjectreviews"}, Verbs: []string{"create"}}, {APIGroups: []string{"authorization.k8s.io"}, Resources: []string{"selfsubjectaccessreviews", "selfsubjectrulesreviews"}, Verbs: []string{"create"}}}
	_, err = c.client.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: "identity"}, Rules: identity}, meta.CreateOptions{})
	if err != nil {
		t.Fatal("synthetic identity grant failed")
	}
	bind(t, ctx, c.client, identityNS, "identity", "ClusterRole", append(append([]string{}, names...), "issuer"))
	read := []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"nodes", "pods", "services", "namespaces", "endpoints", "persistentvolumes", "persistentvolumeclaims", "replicationcontrollers"}, Verbs: []string{"get", "list", "watch"}},
		{APIGroups: []string{"apps"}, Resources: []string{"daemonsets", "replicasets", "statefulsets"}, Verbs: []string{"get", "list", "watch"}},
		{APIGroups: []string{"batch"}, Resources: []string{"jobs"}, Verbs: []string{"get", "list", "watch"}},
		{APIGroups: []string{"resource.k8s.io"}, Resources: []string{"deviceclasses", "resourceclaims", "resourceslices"}, Verbs: []string{"get", "list", "watch"}},
		{APIGroups: []string{"policy"}, Resources: []string{"poddisruptionbudgets"}, Verbs: []string{"get", "list", "watch"}},
		{APIGroups: []string{"storage.k8s.io"}, Resources: []string{"storageclasses", "csinodes", "csidrivers", "volumeattachments", "csistoragecapacities"}, Verbs: []string{"get", "list", "watch"}},
		{APIGroups: []string{""}, Resources: []string{"events"}, Verbs: []string{"create", "patch"}},
		{APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, ResourceNames: names, Verbs: []string{"get"}},
	}
	_, err = c.client.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: "ca-read-events"}, Rules: read}, meta.CreateOptions{})
	if err != nil {
		t.Fatal("synthetic consumer grant failed")
	}
	bind(t, ctx, c.client, identityNS, "ca-read-events", "ClusterRole", names)
	lifetime := int64(7200)
	issuer, err := c.client.CoreV1().ServiceAccounts(identityNS).CreateToken(ctx, "issuer", &auth.TokenRequest{Spec: auth.TokenRequestSpec{Audiences: []string{c.endpoint}, ExpirationSeconds: &lifetime}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal("restricted synthetic issuer bootstrap failed")
	}
	enabled, longLived := true, false
	sa := accounts["issuer"]
	cluster := config.Cluster{ID: c.name, Enabled: &enabled, Endpoint: c.endpoint, KubeSystemUID: string(system.UID), CASHA256: credential.Hash(publicCA), IdentityNamespace: identityNS, Audiences: []string{c.endpoint}, ExpectedIssuer: config.Principal{Username: "system:serviceaccount:" + identityNS + ":issuer", Groups: []string{"system:serviceaccounts", "system:serviceaccounts:" + identityNS, "system:authenticated"}}, Provider: config.Provider{Type: "SecretIssuer", ServiceAccount: &sa, LongLived: &longLived}, Lifetime: config.Lifetime{RequestedSeconds: 1200, AcceptedMinSeconds: 1190, AcceptedMaxSeconds: 1210, RenewBeforeSeconds: 1170, StopBeforeSeconds: 60, ClockSkewSeconds: 5}}
	for i, name := range names {
		cluster.Consumers = append(cluster.Consumers, config.Consumer{ID: fmt.Sprintf("%s-ca-%d", c.name, i), Enabled: &enabled, ServiceAccount: accounts[name], ReloadPolicy: "TokenFile", PermissionProfile: "ca-read-events"})
	}
	return cluster, []byte(issuer.Status.Token)
}
