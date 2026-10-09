package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/issue"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// This opt-in Linux fixture owns a fresh Docker network and kind API. It tests the provider
// against real JWT authentication, not a deployed controller or kubelet projection reload.
func TestActualKubernetes(t *testing.T) {
	if os.Getenv("REQUESTOR_OIDC_API") != "1" {
		t.Skip("opt-in synthetic Docker/kind API acceptance")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("this synthetic gateway fixture requires a Linux Docker host")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	root := t.TempDir()
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal("fixture entropy unavailable")
	}
	name := "requestor-oidc-" + hex.EncodeToString(nonce)
	network := name + "-network"
	command := func(call context.Context, program string, args ...string) ([]byte, error) {
		c := exec.CommandContext(call, program, args...)
		c.Env = append(os.Environ(), "KIND_EXPERIMENTAL_DOCKER_NETWORK="+network)
		return c.Output() // never emit subprocess output or credentials into test logs
	}
	if _, err := command(ctx, "docker", "network", "create", "--label", "requestor.synthetic="+name, network); err != nil {
		t.Fatal("synthetic Docker network creation failed")
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 3*time.Minute)
		defer done()
		_, _ = command(cleanup, "kind", "delete", "cluster", "--name", name)
		if _, err := command(cleanup, "docker", "network", "rm", network); err != nil {
			t.Error("synthetic fixture network cleanup failed")
		}
	})
	gateway, err := command(ctx, "docker", "network", "inspect", "--format", "{{(index .IPAM.Config 0).Gateway}}", network)
	if err != nil || net.ParseIP(strings.TrimSpace(string(gateway))) == nil {
		t.Fatal("synthetic network gateway unavailable")
	}
	ip := net.ParseIP(strings.TrimSpace(string(gateway)))
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal("synthetic TLS listener unavailable")
	}
	t.Cleanup(func() { _ = listener.Close() })
	issuerURL := "https://" + net.JoinHostPort(ip.String(), strings.Split(listener.Addr().String(), ":")[1])
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("synthetic TLS key unavailable")
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic requestor issuer"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IPAddresses: []net.IP{ip}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		t.Fatal("synthetic TLS certificate unavailable")
	}
	trust := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	caPath := filepath.Join(root, "broker-ca.crt") // public certificate only; keys stay in memory
	if os.WriteFile(caPath, trust, 0600) != nil {
		t.Fatal("synthetic public trust export failed")
	}
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		t.Fatal("synthetic client entropy unavailable")
	}
	secret := hex.EncodeToString(secretBytes)
	b, err := New(Settings{Issuer: issuerURL, ClientID: "fixture-client", ClientSecret: secret, SubjectAudience: "fixture-broker", ChildAudience: "fixture-child", SubjectUsername: "system:serviceaccount:requestor-test:subject", SubjectUID: "not-yet-bound", SubjectGroups: []string{"system:serviceaccounts", "system:serviceaccounts:requestor-test", "system:authenticated"}, Management: fake.NewSimpleClientset()})
	if err != nil {
		t.Fatal("synthetic broker bootstrap failed")
	}
	server := &http.Server{Handler: b, ReadHeaderTimeout: 5 * time.Second}
	t.Cleanup(func() { _ = server.Close() })
	go func() {
		_ = server.Serve(tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}))
	}()
	// Pinned kind 0.33 selects beta3 below Kubernetes 1.36. A version-mismatched
	// patch is silently skipped, so verify effective apiserver flags below as well.
	patch := "apiVersion: kubeadm.k8s.io/v1beta3\nkind: ClusterConfiguration\napiServer:\n  extraArgs:\n"
	flags := [][2]string{{"oidc-issuer-url", issuerURL}, {"oidc-client-id", "fixture-child"}, {"oidc-ca-file", "/etc/requestor-oidc/ca.crt"}, {"oidc-username-claim", "sub"}, {"oidc-username-prefix", "fixture:"}, {"oidc-groups-claim", "groups"}, {"oidc-groups-prefix", "fixture:"}}
	for _, flag := range flags {
		patch += "    " + flag[0] + ": " + strconv.Quote(flag[1]) + "\n"
	}
	patch += "  extraVolumes:\n  - name: requestor-oidc-trust\n    hostPath: /etc/requestor-oidc/ca.crt\n    mountPath: /etc/requestor-oidc/ca.crt\n    readOnly: true\n    pathType: File\n"
	kindConfig := map[string]any{"kind": "Cluster", "apiVersion": "kind.x-k8s.io/v1alpha4", "nodes": []any{map[string]any{"role": "control-plane", "kubeadmConfigPatches": []string{patch}, "extraMounts": []any{map[string]any{"hostPath": caPath, "containerPath": "/etc/requestor-oidc/ca.crt", "readOnly": true}}}}}
	data, _ := json.Marshal(kindConfig)
	configPath, kubeconfig := filepath.Join(root, "kind.json"), filepath.Join(root, "kubeconfig")
	if os.WriteFile(configPath, data, 0600) != nil {
		t.Fatal("synthetic kind configuration export failed")
	}
	if _, err := command(ctx, "kind", "create", "cluster", "--name", name, "--config", configPath, "--kubeconfig", kubeconfig, "--image", "kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0", "--wait", "2m"); err != nil {
		t.Fatal("synthetic JWT-auth kind creation failed")
	}
	raw, err := clientcmd.LoadFromFile(kubeconfig)
	if err != nil || raw.CurrentContext != "kind-"+name || len(raw.Contexts) != 1 {
		t.Fatal("synthetic kubeconfig identity invalid")
	}
	adminConfig, err := clientcmd.NewNonInteractiveClientConfig(*raw, "kind-"+name, &clientcmd.ConfigOverrides{}, nil).ClientConfig()
	if err != nil {
		t.Fatal("synthetic kubeconfig invalid")
	}
	endpoint, err := url.Parse(adminConfig.Host)
	if err != nil || endpoint.Scheme != "https" || !net.ParseIP(endpoint.Hostname()).IsLoopback() || adminConfig.Insecure || adminConfig.ExecProvider != nil || adminConfig.AuthProvider != nil || adminConfig.Proxy != nil {
		t.Fatal("synthetic API is not an explicit trusted loopback target")
	}
	adminConfig.Timeout = 10 * time.Second
	admin, err := kubernetes.NewForConfig(adminConfig)
	if err != nil {
		t.Fatal("synthetic API client creation failed")
	}
	nodes, err := admin.CoreV1().Nodes().List(ctx, meta.ListOptions{})
	if err != nil || len(nodes.Items) != 1 || nodes.Items[0].Name != name+"-control-plane" {
		t.Fatal("synthetic API node ownership invalid")
	}
	apiserver, err := admin.CoreV1().Pods("kube-system").Get(ctx, "kube-apiserver-"+name+"-control-plane", meta.GetOptions{})
	if err != nil || len(apiserver.Spec.Containers) != 1 {
		t.Fatal("synthetic apiserver configuration unavailable")
	}
	for _, flag := range flags {
		found := false
		for _, argument := range apiserver.Spec.Containers[0].Command {
			found = found || argument == "--"+flag[0]+"="+flag[1]
		}
		if !found {
			t.Fatal("synthetic apiserver OIDC patch did not take effect")
		}
	}
	system, err := admin.CoreV1().Namespaces().Get(ctx, "kube-system", meta.GetOptions{})
	if err != nil {
		t.Fatal("synthetic API UID unavailable")
	}
	consumer, subject := bootstrapActual(t, ctx, admin)
	mint := func(namespace, account, audience string) string {
		t.Helper()
		ttl := int64(900)
		response, err := admin.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, account, &auth.TokenRequest{Spec: auth.TokenRequestSpec{Audiences: []string{audience}, ExpirationSeconds: &ttl}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal("synthetic bootstrap TokenRequest failed")
		}
		return response.Status.Token
	}
	apiAudience := "https://kubernetes.default.svc.cluster.local"
	restricted := func(account string) kubernetes.Interface {
		t.Helper()
		c, err := kubernetes.NewForConfig(&rest.Config{Host: adminConfig.Host, BearerToken: mint("requestor-test", account, apiAudience), TLSClientConfig: rest.TLSClientConfig{CAData: adminConfig.CAData}, Timeout: 10 * time.Second})
		if err != nil {
			t.Fatal("restricted synthetic client creation failed")
		}
		return c
	}
	if b.BindReviewer(restricted("reviewer"), string(subject.UID)) != nil {
		t.Fatal("actual subject reviewer binding failed")
	}
	refs := map[string]config.Ref{}
	for name, contents := range map[string]map[string][]byte{"trust": {"ca.crt": trust, "api-ca.crt": adminConfig.CAData}, "client": {"client-secret": []byte(secret)}} {
		s, err := admin.CoreV1().Secrets("requestor-test").Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: name}, Type: core.SecretTypeOpaque, Data: contents}, meta.CreateOptions{})
		if err != nil {
			t.Fatal("synthetic provider source creation failed")
		}
		refs[name] = config.Ref{Namespace: s.Namespace, Name: s.Name, UID: string(s.UID)}
	}
	trustRef, clientRef := refs["trust"], refs["client"]
	enabled := true
	cluster := config.Cluster{ID: "jwt-child", Enabled: &enabled, Endpoint: adminConfig.Host, KubeSystemUID: string(system.UID), CASHA256: credential.Hash(adminConfig.CAData), IdentityNamespace: "requestor-identity", Audiences: []string{apiAudience}, ExpectedIssuer: config.Principal{Username: "fixture:issuer", Groups: []string{"fixture:issuers", "system:authenticated"}}, Provider: config.Provider{Type: "OAuthTokenExchange", TokenEndpoint: issuerURL + "/token", TrustSecret: &trustRef, ClientSecret: &clientRef, ClientID: "fixture-client", SubjectTokenVolume: "fixture", SubjectTokenAudience: "fixture-broker", Audience: "fixture-child", Scopes: []string{"issue"}, AcceptedMinSeconds: 590, AcceptedMaxSeconds: 610}, Lifetime: config.Lifetime{RequestedSeconds: 600, AcceptedMinSeconds: 590, AcceptedMaxSeconds: 610, RenewBeforeSeconds: 300, StopBeforeSeconds: 60, ClockSkewSeconds: 5}, Consumers: []config.Consumer{{ID: "ca-one", ServiceAccount: config.ServiceAccount{Name: consumer.Name, UID: string(consumer.UID)}}}}
	subjectToken := mint("requestor-test", "subject", "fixture-broker")
	p := provider.OAuthTokenExchange{Management: restricted("reader"), Now: time.Now, Subject: func(string) ([]byte, error) { return []byte(subjectToken), nil }}
	acquire := func() (provider.IssuerCredential, kubernetes.Interface) {
		t.Helper()
		identity, err := p.Acquire(ctx, cluster)
		if err != nil {
			t.Fatal("actual OAuth exchange failed")
		}
		client, err := issue.Client(cluster.Endpoint, identity)
		if err != nil {
			t.Fatal("actual JWT API client creation failed")
		}
		for attempt := range 20 {
			if err := issue.Issuer(ctx, client, cluster); err == nil {
				return identity, client
			}
			if attempt == 19 {
				t.Logf("JWT fixture diagnostics: discovery=%d jwks=%d identityClass=%v", b.discoveryRequests.Load(), b.jwksRequests.Load(), provider.Classify(issue.Identity(ctx, client, cluster, cluster.ExpectedIssuer)))
				result, reviewErr := admin.AuthenticationV1().TokenReviews().Create(ctx, &auth.TokenReview{Spec: auth.TokenReviewSpec{Token: identity.Bearer}}, meta.CreateOptions{})
				if reviewErr == nil {
					t.Logf("actual JWT review: authenticated=%t username=%q groups=%v errorPresent=%t", result.Status.Authenticated, result.Status.User.Username, result.Status.User.Groups, result.Status.Error != "")
				}
				t.Fatal("real API rejected the restricted JWT issuer")
			}
			time.Sleep(time.Second)
		}
		panic("unreachable")
	}
	_, oldClient := acquire()
	wrongUID := cluster
	wrongUID.KubeSystemUID = "00000000-0000-4000-8000-000000000000"
	if issue.Identity(ctx, oldClient, wrongUID, cluster.ExpectedIssuer) != provider.Trust {
		t.Fatal("wrong actual API UID was accepted")
	}
	wrongTrust := cluster
	wrongTrust.CASHA256 = strings.Repeat("0", 64)
	if _, err := p.Acquire(ctx, wrongTrust); err != provider.Trust {
		t.Fatal("wrong child CA trust was accepted")
	}
	candidate, err := issue.Request(ctx, oldClient, cluster, cluster.Consumers[0], adminConfig.CAData, time.Now())
	if err != nil {
		t.Fatal("real named TokenRequest/consumer permission validation failed")
	}
	if b.RotateKey(false) != nil {
		t.Fatal("synthetic JWKS rotation failed")
	}
	_, _ = acquire() // a new kid forces the real API to refresh discovery/JWKS
	oldRejected := false
	for range 60 {
		if issue.Identity(ctx, oldClient, cluster, cluster.ExpectedIssuer) == provider.Auth {
			oldRejected = true
			break
		}
		time.Sleep(time.Second)
	}
	if !oldRejected {
		t.Fatal("old JWT remained trusted after actual API JWKS refresh")
	}
	if b.ReplaceClientSecret(secret+"-replacement") != nil {
		t.Fatal("synthetic client rotation failed")
	}
	if _, err := p.Acquire(ctx, cluster); err != provider.Auth {
		t.Fatal("old client credential remained accepted")
	}
	s, err := admin.CoreV1().Secrets("requestor-test").Get(ctx, "client", meta.GetOptions{})
	if err != nil || string(s.UID) != clientRef.UID {
		t.Fatal("pinned synthetic client source changed identity")
	}
	s.Data["client-secret"] = []byte(secret + "-replacement")
	if _, err := admin.CoreV1().Secrets(s.Namespace).Update(ctx, s, meta.UpdateOptions{}); err != nil {
		t.Fatal("synthetic client source CAS update failed")
	}
	_, _ = acquire()
	uid := subject.UID
	if admin.CoreV1().ServiceAccounts(subject.Namespace).Delete(ctx, subject.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &uid}}) != nil {
		t.Fatal("synthetic subject revocation failed")
	}
	subjectRejected := false
	for range 60 {
		if _, err := p.Acquire(ctx, cluster); err == provider.Auth {
			subjectRejected = true
			break
		}
		time.Sleep(time.Second)
	}
	if !subjectRejected {
		t.Fatal("revoked actual subject still exchanged after bounded API cache grace")
	}
	caClient, err := issue.Client(cluster.Endpoint, provider.IssuerCredential{Bearer: candidate.Token, CA: candidate.CA})
	if err != nil || issue.ValidateConsumer(ctx, caClient, cluster, cluster.Consumers[0]) != nil {
		t.Fatal("independent CA credential was invalidated by issuer rotation")
	}
	t.Log("actual JWT API acceptance passed: restricted issuer/consumer rights, named TokenRequest, JWKS predecessor rejection, client-source rotation, subject UID revocation; no deployed controller/projection or operator cluster")
}

func bootstrapActual(t *testing.T, ctx context.Context, client kubernetes.Interface) (*core.ServiceAccount, *core.ServiceAccount) {
	t.Helper()
	for _, namespace := range []string{"requestor-test", "requestor-identity"} {
		if _, err := client.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: namespace}}, meta.CreateOptions{}); err != nil {
			t.Fatal("synthetic namespace bootstrap failed")
		}
	}
	accounts := map[string]*core.ServiceAccount{}
	for _, name := range []string{"subject", "reviewer", "reader", "ca-one"} {
		namespace := "requestor-test"
		if name == "ca-one" {
			namespace = "requestor-identity"
		}
		sa, err := client.CoreV1().ServiceAccounts(namespace).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: name}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal("synthetic account bootstrap failed")
		}
		accounts[name] = sa
	}
	roles := []rbac.Role{{ObjectMeta: meta.ObjectMeta{Name: "reader", Namespace: "requestor-test"}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{"trust", "client"}, Verbs: []string{"get"}}}}, {ObjectMeta: meta.ObjectMeta{Name: "issuer", Namespace: "requestor-identity"}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, ResourceNames: []string{"ca-one"}, Verbs: []string{"create"}}, {APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, ResourceNames: []string{"ca-one"}, Verbs: []string{"get"}}}}, {ObjectMeta: meta.ObjectMeta{Name: "ca-events", Namespace: "requestor-identity"}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"events"}, Verbs: []string{"create", "patch"}}}}}
	for _, role := range roles {
		if _, err := client.RbacV1().Roles(role.Namespace).Create(ctx, &role, meta.CreateOptions{}); err != nil {
			t.Fatal("synthetic namespaced rights bootstrap failed")
		}
	}
	clusterRoles := []rbac.ClusterRole{{ObjectMeta: meta.ObjectMeta{Name: "fixture-reviewer"}, Rules: []rbac.PolicyRule{{APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"tokenreviews"}, Verbs: []string{"create"}}}}, {ObjectMeta: meta.ObjectMeta{Name: "fixture-identity"}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{"kube-system"}, Verbs: []string{"get"}}, {APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"selfsubjectreviews"}, Verbs: []string{"create"}}, {APIGroups: []string{"authorization.k8s.io"}, Resources: []string{"selfsubjectaccessreviews", "selfsubjectrulesreviews"}, Verbs: []string{"create"}}}}, {ObjectMeta: meta.ObjectMeta{Name: "fixture-ca"}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"nodes", "pods", "services"}, Verbs: []string{"get", "list", "watch"}}, {APIGroups: []string{"apps"}, Resources: []string{"daemonsets"}, Verbs: []string{"get", "list", "watch"}}, {APIGroups: []string{"policy"}, Resources: []string{"poddisruptionbudgets"}, Verbs: []string{"get", "list", "watch"}}, {APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, ResourceNames: []string{"ca-one"}, Verbs: []string{"get"}}}}}
	for _, role := range clusterRoles {
		if _, err := client.RbacV1().ClusterRoles().Create(ctx, &role, meta.CreateOptions{}); err != nil {
			t.Fatal("synthetic API rights bootstrap failed")
		}
	}
	subject := func(name string) rbac.Subject {
		return rbac.Subject{Kind: "ServiceAccount", Namespace: accounts[name].Namespace, Name: name}
	}
	user := rbac.Subject{APIGroup: rbac.GroupName, Kind: "User", Name: "fixture:issuer"}
	for _, binding := range []rbac.RoleBinding{{ObjectMeta: meta.ObjectMeta{Name: "reader", Namespace: "requestor-test"}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: "reader"}, Subjects: []rbac.Subject{subject("reader")}}, {ObjectMeta: meta.ObjectMeta{Name: "issuer", Namespace: "requestor-identity"}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: "issuer"}, Subjects: []rbac.Subject{user}}, {ObjectMeta: meta.ObjectMeta{Name: "ca-events", Namespace: "requestor-identity"}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: "ca-events"}, Subjects: []rbac.Subject{subject("ca-one")}}} {
		if _, err := client.RbacV1().RoleBindings(binding.Namespace).Create(ctx, &binding, meta.CreateOptions{}); err != nil {
			t.Fatal("synthetic namespaced binding failed")
		}
	}
	for _, binding := range []rbac.ClusterRoleBinding{{ObjectMeta: meta.ObjectMeta{Name: "fixture-reviewer"}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: "fixture-reviewer"}, Subjects: []rbac.Subject{subject("reviewer")}}, {ObjectMeta: meta.ObjectMeta{Name: "fixture-identity"}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: "fixture-identity"}, Subjects: []rbac.Subject{user, subject("ca-one")}}, {ObjectMeta: meta.ObjectMeta{Name: "fixture-ca"}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: "fixture-ca"}, Subjects: []rbac.Subject{subject("ca-one")}}} {
		if _, err := client.RbacV1().ClusterRoleBindings().Create(ctx, &binding, meta.CreateOptions{}); err != nil {
			t.Fatal("synthetic API binding failed")
		}
	}
	return accounts["ca-one"], accounts["subject"]
}
