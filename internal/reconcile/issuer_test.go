package reconcile

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/issue"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/publish"
	"github.com/rayselfs/kube-token-requestor/internal/status"
	"github.com/rayselfs/kube-token-requestor/internal/testutil"
	apps "k8s.io/api/apps/v1"
	auth "k8s.io/api/authentication/v1"
	authz "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
	kt "k8s.io/client-go/testing"
)

// A synthetic HTTPS API exercises actual successor authentication, not decoded claims alone.
func issuerFixture(t *testing.T, mode string) (*Engine, config.Cluster, *atomic.Int64) {
	t.Helper()
	now := time.Unix(2000000000, 0)
	requests := &atomic.Int64{}
	disabled := false
	c := config.Cluster{ID: "child", IdentityNamespace: "identity", KubeSystemUID: "cluster-uid", Audiences: []string{"api"}, ExpectedIssuer: config.Principal{Username: "system:serviceaccount:identity:issuer", Groups: []string{"system:authenticated"}}, Provider: config.Provider{Type: "SecretIssuer", Secret: &config.Ref{Namespace: "management", Name: "source", UID: "source-uid"}, ServiceAccount: &config.ServiceAccount{Name: "issuer", UID: "issuer-uid"}, LongLived: &disabled, Renewal: &config.Lifetime{RequestedSeconds: 3600, AcceptedMinSeconds: 3500, AcceptedMaxSeconds: 3700, RenewBeforeSeconds: 1800, StopBeforeSeconds: 60, ClockSkewSeconds: 5}}, Consumers: []config.Consumer{{ServiceAccount: config.ServiceAccount{Name: "ca", UID: "ca-uid"}}}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var response any
		switch r.URL.Path {
		case "/version":
			response = map[string]string{"major": "1", "minor": "35"}
		case "/api/v1/namespaces/kube-system":
			response = &core.Namespace{ObjectMeta: meta.ObjectMeta{UID: "cluster-uid"}}
		case "/apis/authentication.k8s.io/v1/selfsubjectreviews":
			username := c.ExpectedIssuer.Username
			if mode == "wrong-principal" {
				username = "foreign"
			}
			if mode == "revoked" {
				w.WriteHeader(401)
				return
			}
			response = &auth.SelfSubjectReview{Status: auth.SelfSubjectReviewStatus{UserInfo: auth.UserInfo{Username: username, Groups: c.ExpectedIssuer.Groups}}}
		case "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews":
			names := []string{"issuer", "ca"}
			if mode == "broad-permissions" {
				names = append(names, "foreign")
			}
			response = &authz.SelfSubjectRulesReview{Status: authz.SubjectRulesReviewStatus{ResourceRules: []authz.ResourceRule{{APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, Verbs: []string{"create"}, ResourceNames: names}}}}
		case "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
			var q authz.SelfSubjectAccessReview
			body, _ := io.ReadAll(r.Body)
			if _, _, err := scheme.Codecs.UniversalDeserializer().Decode(body, nil, &q); err != nil {
				t.Error("invalid synthetic request", err)
				w.WriteHeader(400)
				return
			}
			a := q.Spec.ResourceAttributes
			response = &authz.SelfSubjectAccessReview{Status: authz.SubjectAccessReviewStatus{Allowed: a.Resource == "serviceaccounts" && a.Subresource == "token" && (a.Name == "issuer" || a.Name == "ca")}}
		case "/api/v1/namespaces/identity/serviceaccounts/issuer":
			response = &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{UID: "issuer-uid"}}
		case "/api/v1/namespaces/identity/serviceaccounts/ca":
			if mode == "missing-consumer" {
				w.WriteHeader(404)
				return
			}
			response = &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{UID: "ca-uid"}}
		case "/api/v1/namespaces/identity/serviceaccounts/issuer/token":
			requests.Add(1)
			if mode == "rate-limit" {
				w.Header().Set("Retry-After", "120")
				w.WriteHeader(429)
				return
			}
			if mode == "transport" {
				w.WriteHeader(503)
				return
			}
			var q auth.TokenRequest
			body, _ := io.ReadAll(r.Body)
			if _, _, err := scheme.Codecs.UniversalDeserializer().Decode(body, nil, &q); err != nil {
				t.Error("invalid synthetic request", err)
				w.WriteHeader(400)
				return
			}
			if q.Spec.ExpirationSeconds == nil || *q.Spec.ExpirationSeconds != 3600 || !credential.SameSet(q.Spec.Audiences, []string{"api"}) {
				t.Error("wrong request policy")
			}
			sa, uid, aud, ttl := "issuer", "issuer-uid", []string{"api"}, int64(3600)
			switch mode {
			case "wrong-sa":
				sa = "foreign"
			case "wrong-uid":
				uid = "foreign"
			case "wrong-audience":
				aud = []string{"foreign"}
			case "short-ttl":
				ttl = 60
			case "oversize-ttl":
				ttl = 7200
			}
			token := testutil.Token("system:serviceaccount:identity:"+sa, "identity", sa, uid, aud, now, ttl)
			exp := now.Add(time.Duration(ttl) * time.Second)
			if mode == "expiry-mismatch" {
				exp = exp.Add(time.Second)
			}
			response = &auth.TokenRequest{Status: auth.TokenRequestStatus{Token: token, ExpirationTimestamp: meta.NewTime(exp)}}
		default:
			t.Errorf("unexpected API path %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	t.Cleanup(server.Close)
	c.Endpoint = server.URL
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	c.CASHA256 = credential.Hash(ca)
	source := &core.Secret{ObjectMeta: meta.ObjectMeta{Namespace: "management", Name: "source", UID: "source-uid", ResourceVersion: "10", Annotations: map[string]string{"operator": "preserve"}}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"ca.crt": ca, "token": []byte(testutil.Token(c.ExpectedIssuer.Username, "identity", "issuer", "issuer-uid", c.Audiences, now.Add(-3000*time.Second), 3600))}}
	client := fake.NewClientset(source)
	e := &Engine{Management: client, Now: func() time.Time { return now }, Current: func(context.Context, string) error { return nil }}
	return e, c, requests
}

func TestIssuerRenewalAuthenticatesAndPersistsSuccessor(t *testing.T) {
	e, c, requests := issuerFixture(t, "valid")
	ctx := context.Background()
	p := provider.SecretIssuer{Management: e.Management, Now: e.Now}
	identity, err := p.Acquire(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	client, err := issue.Client(c.Endpoint, identity)
	if err != nil {
		t.Fatal(err)
	}
	if err = issue.Issuer(ctx, client, c); err != nil {
		t.Fatal("original issuer validation failed", err)
	}
	successor, fresh, err := e.renewIssuer(ctx, c, "generation", client, identity)
	if err != nil || successor == nil || fresh.Bearer == identity.Bearer || requests.Load() != 1 {
		t.Fatal("renewal did not publish authenticated successor", err)
	}
	stored, err := p.Acquire(ctx, c)
	if err != nil || stored.Bearer != fresh.Bearer {
		t.Fatal("new leader cannot acquire successor", err)
	}
	_, again, err := e.renewIssuer(ctx, c, "generation", successor, stored)
	if err != nil || again.Bearer != fresh.Bearer || requests.Load() != 1 {
		t.Fatal("not-due source renewed again")
	}
	obj, _ := e.Management.CoreV1().Secrets("management").Get(ctx, "source", meta.GetOptions{})
	if obj.UID != "source-uid" || obj.Annotations["operator"] != "preserve" || len(obj.Data) != 2 || credential.Hash(obj.Data["ca.crt"]) != c.CASHA256 {
		t.Fatal("source metadata/trust changed")
	}
	for _, a := range e.Management.(*fake.Clientset).Actions() {
		if a.GetVerb() == "patch" && a.GetResource().Resource != "secrets" {
			t.Fatal("source renewal touched workloads")
		}
	}
}

func TestIssuerRenewalRejectsUnsafeSuccessorsWithoutPublication(t *testing.T) {
	for _, mode := range []string{"wrong-sa", "wrong-uid", "wrong-audience", "short-ttl", "oversize-ttl", "expiry-mismatch", "wrong-principal", "broad-permissions", "revoked", "transport", "stale-before-mint", "stale-before-publish", "cas-conflict", "response-lost", "source-drift", "missing-fence", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			e, c, requests := issuerFixture(t, mode)
			ctx := context.Background()
			p := provider.SecretIssuer{Management: e.Management, Now: e.Now}
			identity, err := p.Acquire(ctx, c)
			if err != nil {
				t.Fatal(err)
			}
			client, err := issue.Client(c.Endpoint, identity)
			if err != nil {
				t.Fatal(err)
			}
			checks := 0
			e.Current = func(context.Context, string) error {
				checks++
				if mode == "stale-before-mint" || (mode == "stale-before-publish" && checks == 2) {
					return provider.Conflict
				}
				return nil
			}
			if mode == "missing-fence" {
				e.Current = nil
			}
			if mode == "legacy" {
				c.Provider.Renewal = nil
			}
			if mode == "cas-conflict" || mode == "response-lost" {
				e.Management.(*fake.Clientset).PrependReactor("patch", "secrets", func(a kt.Action) (bool, runtime.Object, error) {
					if mode == "response-lost" {
						obj, _ := e.Management.(*fake.Clientset).Tracker().Get(core.SchemeGroupVersion.WithResource("secrets"), "management", "source")
						s := obj.(*core.Secret).DeepCopy()
						s.Data["token"] = []byte(testutil.Token(c.ExpectedIssuer.Username, "identity", "issuer", "issuer-uid", c.Audiences, e.Now(), 3600))
						_ = e.Management.(*fake.Clientset).Tracker().Update(core.SchemeGroupVersion.WithResource("secrets"), s, "management")
						return true, nil, fmt.Errorf("response lost")
					}
					return true, nil, provider.Conflict
				})
			}
			if mode == "source-drift" {
				identity.Bearer += "different"
			}
			_, _, err = e.renewIssuer(ctx, c, "generation", client, identity)
			if mode == "legacy" {
				if err != nil || requests.Load() != 0 {
					t.Fatal("legacy enrollment changed")
				}
				return
			}
			if err == nil {
				t.Fatal("unsafe source accepted")
			}
			if strings.Contains(err.Error(), "eyJ") {
				t.Fatal("credential leaked")
			}
			stored, _ := p.Acquire(ctx, c)
			if mode == "response-lost" {
				if stored.Bearer == identity.Bearer {
					t.Fatal("successor not recoverable after lost response")
				}
				return
			}
			obj, _ := e.Management.CoreV1().Secrets("management").Get(ctx, "source", meta.GetOptions{})
			want := identity.Bearer
			if mode == "source-drift" {
				want = strings.TrimSuffix(want, "different")
			}
			if string(obj.Data["token"]) != want {
				t.Fatal("failure overwrote predecessor")
			}
			if (mode == "stale-before-mint" || mode == "missing-fence" || mode == "source-drift") && requests.Load() != 0 {
				t.Fatal("mint preceded fence")
			}
		})
	}
}

func TestExpiredSourceRequiresRebootstrapWithoutIssuance(t *testing.T) {
	e, c, requests := issuerFixture(t, "valid")
	ctx := context.Background()
	source, _ := e.Management.CoreV1().Secrets("management").Get(ctx, "source", meta.GetOptions{})
	source.Data["token"] = []byte(testutil.Token(c.ExpectedIssuer.Username, "identity", "issuer", "issuer-uid", c.Audiences, e.Now().Add(-time.Hour), 600))
	_, _ = e.Management.CoreV1().Secrets("management").Update(ctx, source, meta.UpdateOptions{})
	p := provider.SecretIssuer{Management: e.Management, Now: e.Now}
	if _, err := p.Acquire(ctx, c); err != provider.Auth {
		t.Fatal("expired issuer silently recovered")
	}
	if requests.Load() != 0 {
		t.Fatal("mint with expired source")
	}
}

func TestSourceRenewalUsesClusterQueueNotConsumerDeadline(t *testing.T) {
	for _, mode := range []string{"valid", "disabled-cluster", "rate-limit", "missing-consumer"} {
		t.Run(mode, func(t *testing.T) {
			e, c, requests := issuerFixture(t, mode)
			ctx := context.Background()
			enabled, disabled := true, false
			c.Enabled = &enabled
			c.Lifetime = *c.Provider.Renewal
			consumer := &c.Consumers[0]
			consumer.ID = "ca"
			consumer.Enabled = &disabled
			consumer.Secret = config.Ref{Namespace: "management", Name: "output", UID: "output-uid"}
			consumer.CADeployment = config.Deployment{Namespace: "management", Name: "ca", UID: "deployment-uid", ImageDigest: "sha256:" + strings.Repeat("1", 64)}
			consumer.ReloadPolicy = "StopStart"
			source, _ := e.Management.CoreV1().Secrets("management").Get(ctx, "source", meta.GetOptions{})
			replicas := int32(0)
			_, _ = e.Management.CoreV1().Secrets("management").Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Namespace: "management", Name: "output", UID: "output-uid", Annotations: map[string]string{publish.Owner: "ca"}}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"ca.crt": source.Data["ca.crt"], "token": []byte(testutil.Token("system:serviceaccount:identity:ca", "identity", "ca", "ca-uid", c.Audiences, e.Now(), 3600))}}, meta.CreateOptions{})
			_, _ = e.Management.AppsV1().Deployments("management").Create(ctx, &apps.Deployment{ObjectMeta: meta.ObjectMeta{Namespace: "management", Name: "ca", UID: "deployment-uid"}, Spec: apps.DeploymentSpec{Replicas: &replicas, Template: core.PodTemplateSpec{Spec: core.PodSpec{Containers: []core.Container{{Image: "test@" + consumer.CADeployment.ImageDigest}}}}}}, meta.CreateOptions{})
			_, _ = e.Management.CoreV1().ConfigMaps("management").Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Namespace: "management", Name: "status", UID: "status-uid"}}, meta.CreateOptions{})
			e.Store = &status.Store{Client: e.Management, Namespace: "management", Name: "status", UID: "status-uid"}
			e.Providers = map[string]provider.IssuerProvider{"SecretIssuer": provider.SecretIssuer{Management: e.Management, Now: e.Now}}
			if mode == "disabled-cluster" {
				c.Enabled = &disabled
			}
			if mode == "missing-consumer" {
				consumer.Enabled = &enabled
			}
			err := e.Slice(ctx, c, "generation", 0, true)
			if mode == "rate-limit" {
				var retry *provider.Retry
				if !errors.As(err, &retry) {
					t.Fatal("renewal Retry-After lost", err)
				}
				_ = e.Slice(ctx, c, "generation", 0, true)
				if requests.Load() != 1 {
					t.Fatal("renewal bypassed Retry-After")
				}
				return
			}
			if (err != nil) != (mode == "missing-consumer") {
				t.Fatal("incorrect source/consumer failure isolation", err)
			}
			want := int64(1)
			if mode == "disabled-cluster" {
				want = 0
			}
			if requests.Load() != want {
				t.Fatal("consumer/cluster enable incorrectly gated source renewal")
			}
			fresh, _ := e.Management.CoreV1().Secrets("management").Get(ctx, "source", meta.GetOptions{})
			if (string(fresh.Data["token"]) != string(source.Data["token"])) != (mode == "valid" || mode == "missing-consumer") {
				t.Fatal("unexpected source publication")
			}
			// A new process resumes from persisted source without any in-memory renewal state.
			successor := &Engine{Management: e.Management, Now: e.Now, Current: e.Current, Store: e.Store, Providers: e.Providers}
			if err = successor.Slice(ctx, c, "generation", 0, true); (err != nil) != (mode == "missing-consumer") || requests.Load() != want {
				t.Fatal("leader restart repeated source issuance", err)
			}
			for _, a := range e.Management.(*fake.Clientset).Actions() {
				if a.GetVerb() == "patch" && (a.GetResource().Resource != "secrets" || a.(kt.PatchAction).GetName() != "source") {
					t.Fatal("source renewal changed CA or consumer")
				}
			}
		})
	}
}

func TestRenewableSourceRejectsInvalidBootstrapClaims(t *testing.T) {
	for _, mode := range []string{"valid-aged", "wrong-uid", "wrong-namespace", "wrong-audience", "future-issued", "long-ttl", "short-ttl", "inside-safety"} {
		t.Run(mode, func(t *testing.T) {
			e, c, requests := issuerFixture(t, "valid")
			ctx := context.Background()
			source, _ := e.Management.CoreV1().Secrets("management").Get(ctx, "source", meta.GetOptions{})
			issued := e.Now().Add(-time.Minute)
			ttl := int64(3600)
			namespace, uid, aud := "identity", "issuer-uid", []string{"api"}
			switch mode {
			case "wrong-uid":
				uid = "foreign"
			case "wrong-namespace":
				namespace = "foreign"
			case "wrong-audience":
				aud = []string{"foreign"}
			case "future-issued":
				issued = e.Now().Add(time.Minute)
			case "long-ttl":
				ttl = 7200
			case "short-ttl":
				ttl = 1800
			case "inside-safety":
				issued = e.Now().Add(-3550 * time.Second)
			}
			source.Data["token"] = []byte(testutil.Token(c.ExpectedIssuer.Username, namespace, "issuer", uid, aud, issued, ttl))
			_, _ = e.Management.CoreV1().Secrets("management").Update(ctx, source, meta.UpdateOptions{})
			p := provider.SecretIssuer{Management: e.Management, Now: e.Now}
			_, err := p.Acquire(ctx, c)
			if (err == nil) != (mode == "valid-aged") {
				t.Fatal("bootstrap source claim policy incorrect", err)
			}
			if requests.Load() != 0 {
				t.Fatal("acquisition unexpectedly minted")
			}
		})
	}
}
