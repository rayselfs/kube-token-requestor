package reconcile

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	authz "k8s.io/api/authorization/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/issue"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/publish"
	"github.com/rayselfs/kube-token-requestor/internal/status"
	"github.com/rayselfs/kube-token-requestor/internal/testutil"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestAccessPublicationAndIsolation(t *testing.T) {
	for _, mode := range []string{"rotate", "disabled", "expired", "revoked", "wrong-secret", "stale", "acquisition", "latched"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Unix(2000000000, 0)
			yes := true
			consumer := config.Consumer{ID: "access", Enabled: &yes, ServiceAccount: config.ServiceAccount{Name: "gateway", UID: "sa-uid"}, Secret: config.Ref{Namespace: "management", Name: "output", UID: "output-uid"}, Access: &config.Access{Users: []string{"reader@example.invalid"}, Groups: []string{}}, ReloadPolicy: "TokenFile", PermissionProfile: "access-impersonation"}
			c := config.Cluster{ID: "target", Enabled: &yes, IdentityNamespace: "identity", KubeSystemUID: "cluster-uid", Audiences: []string{"api"}, Lifetime: config.Lifetime{RequestedSeconds: 3600, AcceptedMinSeconds: 3500, AcceptedMaxSeconds: 3700, RenewBeforeSeconds: 1800, StopBeforeSeconds: 60, ClockSkewSeconds: 5}, Consumers: []config.Consumer{consumer}}
			token := func(lifetime int64) string {
				return testutil.Token("system:serviceaccount:identity:gateway", "identity", "gateway", "sa-uid", []string{"api"}, now, lifetime)
			}
			requests := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				var out any
				switch r.URL.Path {
				case "/version":
					out = map[string]string{"major": "1", "minor": "35"}
				case "/api/v1/namespaces/kube-system":
					out = map[string]any{"metadata": map[string]string{"uid": "cluster-uid"}}
				case "/api/v1/namespaces/identity/serviceaccounts/gateway":
					out = map[string]any{"metadata": map[string]string{"uid": "sa-uid"}}
				case "/apis/authentication.k8s.io/v1/selfsubjectreviews":
					if mode == "revoked" {
						w.WriteHeader(401)
						return
					}
					out = map[string]any{"status": map[string]any{"userInfo": map[string]any{"username": "system:serviceaccount:identity:gateway", "groups": []string{"system:serviceaccounts", "system:serviceaccounts:identity", "system:authenticated"}}}}
				case "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews":
					out = map[string]any{"status": map[string]any{"resourceRules": []any{map[string]any{"apiGroups": []string{""}, "resources": []string{"users"}, "verbs": []string{"impersonate"}, "resourceNames": consumer.Access.Users}}}}
				case "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
					var q authz.SelfSubjectAccessReview
					body, _ := io.ReadAll(r.Body)
					if _, _, err := scheme.Codecs.UniversalDeserializer().Decode(body, nil, &q); err != nil {
						t.Error(err)
						w.WriteHeader(400)
						return
					}
					a := q.Spec.ResourceAttributes
					allowed := a.Verb == "impersonate" && a.Resource == "users" && a.Name == "reader@example.invalid"
					if r.Header.Get("Authorization") == "Bearer "+token(7200) && a.Resource == "serviceaccounts" && a.Subresource == "token" && a.Name == "gateway" {
						allowed = true
					}
					out = map[string]any{"status": map[string]bool{"allowed": allowed}}
				case "/api/v1/namespaces/identity/serviceaccounts/gateway/token":
					requests++
					out = map[string]any{"status": map[string]any{"token": token(3600), "expirationTimestamp": now.Add(time.Hour).Format(time.RFC3339)}}
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
					w.WriteHeader(404)
					return
				}
				json.NewEncoder(w).Encode(out)
			}))
			defer server.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			c.Endpoint = server.URL
			c.CASHA256 = credential.Hash(ca)
			lifetime := int64(1200)
			if mode == "expired" {
				lifetime = -1
			}
			output := &core.Secret{ObjectMeta: meta.ObjectMeta{Namespace: "management", Name: "output", UID: "output-uid", ResourceVersion: "1", Annotations: map[string]string{publish.Owner: "access"}}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"ca.crt": ca, "token": []byte(token(lifetime))}}
			if mode == "wrong-secret" {
				output.UID = "foreign"
			}
			client := fake.NewClientset(output, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Namespace: "management", Name: "status", UID: "status-uid"}})
			e := &Engine{Management: client, Now: func() time.Time { return now }, Store: &status.Store{Client: client, Namespace: "management", Name: "status", UID: "status-uid"}, Current: func(context.Context, string) error {
				if mode == "stale" {
					return provider.Conflict
				}
				return nil
			}}
			identity := provider.IssuerCredential{Bearer: token(7200), CA: ca}
			issuer, err := issue.Client(c.Endpoint, identity)
			if err != nil {
				t.Fatal(err)
			}
			var acq error
			if mode == "acquisition" {
				acq = provider.Transport
			}
			entry := status.Consumer{}
			if mode == "latched" {
				entry.StopLatched = true
			}
			err = e.consumer(context.Background(), c, consumer, "generation", entry, issuer, identity, acq, mode != "disabled")
			if mode == "rotate" {
				if err != nil || requests != 1 {
					t.Fatalf("rotation err=%v requests=%d", err, requests)
				}
				s, _ := e.Store.Read(context.Background())
				if s.Consumers["access"].Condition != "CredentialPublished" {
					t.Fatal("wrong status")
				}
			} else if requests != 0 {
				t.Fatal("unsafe issuance")
			}
			for _, a := range client.Actions() {
				if strings.Contains(a.GetResource().Resource, "deployment") {
					t.Fatal("Access touched CA lifecycle")
				}
			}
			if mode == "expired" && e.Delay(c, time.Minute) != time.Minute {
				t.Fatal("expired Access creates a hot retry loop")
			}
			if mode == "expired" || mode == "revoked" {
				s, _ := e.Store.Read(context.Background())
				if !s.Consumers["access"].StopLatched {
					t.Fatal("missing failure latch")
				}
			}
		})
	}
}
