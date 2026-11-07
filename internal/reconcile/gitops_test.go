package reconcile

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
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
	auth "k8s.io/api/authentication/v1"
	authz "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
)

func TestGitOpsPublicationAndIsolation(t *testing.T) {
	for _, mode := range []string{"rotate", "disabled", "expired", "revoked", "wrong-secret", "stale", "acquisition", "latched", "recover", "reused-ack", "older-replacement"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Unix(2000000000, 0)
			yes := true
			consumer := config.Consumer{ID: "gitops", Enabled: &yes, ServiceAccount: config.ServiceAccount{Name: "gateway", UID: "sa-uid"}, Secret: config.Ref{Namespace: "management", Name: "output", UID: "output-uid"}, GitOps: &config.GitOps{Name: "target", Project: "project", Namespace: "identity", ConfigMap: "probe", EnrollmentUID: "enrollment", BoundSecret: config.Ref{Namespace: "identity", Name: "lease", UID: "lease-uid"}}, ReloadPolicy: "ArgoSecret", PermissionProfile: "gitops-configmap"}
			c := config.Cluster{ID: "target", Enabled: &yes, IdentityNamespace: "identity", KubeSystemUID: "cluster-uid", Audiences: []string{"api"}, Lifetime: config.Lifetime{RequestedSeconds: 3600, AcceptedMinSeconds: 3500, AcceptedMaxSeconds: 3700, RenewBeforeSeconds: 1800, StopBeforeSeconds: 60, ClockSkewSeconds: 5}, Consumers: []config.Consumer{consumer}}
			token := func(lifetime int64) string {
				return testutil.BoundToken("system:serviceaccount:identity:gateway", "identity", "gateway", "sa-uid", []string{"api"}, now, lifetime, "lease", "lease-uid")
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
				case "/api/v1/namespaces/identity/secrets/lease":
					out = map[string]any{"metadata": map[string]string{"uid": "lease-uid"}}
				case "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews":
					out = map[string]any{"status": map[string]any{"resourceRules": []any{map[string]any{"apiGroups": []string{""}, "resources": []string{"configmaps"}, "verbs": []string{"patch", "update"}, "resourceNames": []string{"probe"}}}}}
				case "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
					var q authz.SelfSubjectAccessReview
					body, _ := io.ReadAll(r.Body)
					if _, _, err := scheme.Codecs.UniversalDeserializer().Decode(body, nil, &q); err != nil {
						t.Error(err)
						w.WriteHeader(400)
						return
					}
					a := q.Spec.ResourceAttributes
					allowed := a.Namespace == "identity" && a.Resource == "configmaps" && (a.Verb == "get" || a.Verb == "list" || a.Verb == "watch" || ((a.Verb == "patch" || a.Verb == "update") && a.Name == "probe"))
					if r.Header.Get("Authorization") == "Bearer "+token(7200) && a.Resource == "serviceaccounts" && a.Subresource == "token" && a.Name == "gateway" {
						allowed = true
					}
					out = map[string]any{"status": map[string]bool{"allowed": allowed}}
				case "/api/v1/namespaces/identity/serviceaccounts/gateway/token":
					requests++
					var q auth.TokenRequest
					body, _ := io.ReadAll(r.Body)
					if _, _, err := scheme.Codecs.UniversalDeserializer().Decode(body, nil, &q); err != nil {
						t.Error("invalid request")
						w.WriteHeader(400)
						return
					}
					ref := q.Spec.BoundObjectRef
					if ref == nil || string(ref.UID) != "lease-uid" || ref.Name != "lease" {
						t.Error("missing bound-object request")
					}

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
			output := &core.Secret{ObjectMeta: meta.ObjectMeta{Namespace: "management", Name: "output", UID: "output-uid", ResourceVersion: "1", Annotations: map[string]string{publish.Owner: "gitops"}}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"ca.crt": ca, "token": []byte(token(lifetime))}}
			configJSON, _ := json.Marshal(map[string]any{"bearerToken": token(lifetime), "tlsClientConfig": map[string]any{"insecure": false, "caData": ca}})
			output.Data = map[string][]byte{"name": []byte("target"), "server": []byte(c.Endpoint), "project": []byte("project"), "namespaces": []byte("identity"), "clusterResources": []byte("false"), "config": configJSON}
			output.Labels = map[string]string{"argocd.argoproj.io/secret-type": "cluster"}
			output.Annotations[publish.Enrollment] = "enrollment"
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
			if mode == "latched" || mode == "recover" || mode == "reused-ack" || mode == "older-replacement" {
				entry.StopLatched = true
			}
			if mode == "recover" || mode == "reused-ack" || mode == "older-replacement" {
				output.Annotations[Acknowledge] = "00000000-0000-0000-0000-000000000001"
				entry.Expiry = now.Add(60 * time.Second)
				if mode == "reused-ack" {
					entry.Acknowledgement = output.Annotations[Acknowledge]
				}
				if mode == "older-replacement" {
					entry.Expiry = now.Add(2400 * time.Second)
				}
				if _, err := client.CoreV1().Secrets(output.Namespace).Update(context.Background(), output, meta.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			err = e.consumer(context.Background(), c, consumer, "generation", entry, issuer, identity, acq, mode != "disabled")
			if mode == "rotate" || mode == "recover" {
				if err != nil || requests != 1 {
					t.Fatalf("rotation err=%v requests=%d", err, requests)
				}
				s, _ := e.Store.Read(context.Background())
				if s.Consumers["gitops"].Condition != "CredentialPublished" {
					t.Fatal("wrong status")
				}
			} else if requests != 0 {
				t.Fatal("unsafe issuance")
			}
			if (mode == "reused-ack" || mode == "older-replacement") && err == nil {
				t.Fatal("unsafe recovery accepted")
			}
			for _, a := range client.Actions() {
				if strings.Contains(a.GetResource().Resource, "deployment") {
					t.Fatal("GitOps touched workload lifecycle")
				}
			}
			if mode == "expired" && e.Delay(c, time.Minute) != time.Minute {
				t.Fatal("expired GitOps creates a hot retry loop")
			}
			if mode == "expired" || mode == "revoked" {
				s, _ := e.Store.Read(context.Background())
				if !s.Consumers["gitops"].StopLatched {
					t.Fatal("missing failure latch")
				}
			}
		})
	}
}
