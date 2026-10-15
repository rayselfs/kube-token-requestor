package reconcile

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/publish"
	"github.com/rayselfs/kube-token-requestor/internal/status"
	"github.com/rayselfs/kube-token-requestor/internal/testutil"
	authz "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
)

func TestValidatedExistingConsumerClearsRecoveredFailure(t *testing.T) {
	for _, mode := range []string{"recovered", "issuer-rejected", "consumer-rejected", "latched", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			requests := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				var reply any
				switch r.URL.Path {
				case "/version":
					reply = map[string]string{"major": "1", "minor": "36"}
				case "/api/v1/namespaces/kube-system":
					childUID := "child-uid"
					if mode == "consumer-rejected" {
						childUID = "foreign-uid"
					}
					reply = map[string]any{"metadata": map[string]string{"uid": childUID}}
				case "/apis/authentication.k8s.io/v1/selfsubjectreviews":
					reply = map[string]any{"status": map[string]any{"userInfo": map[string]any{"username": "system:serviceaccount:identity:ca", "groups": []string{"system:serviceaccounts", "system:serviceaccounts:identity", "system:authenticated"}}}}
				case "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews":
					reply = &authz.SelfSubjectRulesReview{}
				case "/api/v1/namespaces/identity/serviceaccounts/ca":
					reply = &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{UID: "sa-uid"}}
				case "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
						w.WriteHeader(400)
						return
					}
					obj, _, err := scheme.Codecs.UniversalDeserializer().Decode(body, nil, nil)
					if err != nil {
						t.Error(err)
						w.WriteHeader(400)
						return
					}
					a := obj.(*authz.SelfSubjectAccessReview).Spec.ResourceAttributes
					allowed := a.Verb == "list" || a.Resource == "events"
					reply = &authz.SelfSubjectAccessReview{Status: authz.SubjectAccessReviewStatus{Allowed: allowed}}
				default:
					requests++
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(404)
					return
				}
				if err := json.NewEncoder(w).Encode(reply); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			now := time.Unix(2000000000, 0)
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			consumer, deployment := haFixture(0)
			consumer.Secret = config.Ref{Namespace: "ns", Name: "output", UID: "output-uid"}
			consumer.ServiceAccount = config.ServiceAccount{Name: "ca", UID: "sa-uid"}
			consumer.ReloadPolicy = "StopStart"
			consumer.LeaderElectionLease = nil
			consumer.CADeployment.MaxReplicas = nil
			cluster := config.Cluster{Endpoint: server.URL, KubeSystemUID: "child-uid", IdentityNamespace: "identity", CASHA256: credential.Hash(ca), Audiences: []string{"api"}, Lifetime: config.Lifetime{RenewBeforeSeconds: 300, StopBeforeSeconds: 60, ClockSkewSeconds: 5}}
			output := &core.Secret{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "output", UID: "output-uid", Annotations: map[string]string{publish.Owner: consumer.ID}}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"ca.crt": ca, "token": []byte(testutil.Token("system:serviceaccount:identity:ca", "identity", "ca", "sa-uid", []string{"api"}, now, 3600))}}
			client := fake.NewClientset(deployment, output, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "status", UID: "status-uid"}})
			store := &status.Store{Client: client, Namespace: "ns", Name: "status", UID: "status-uid"}
			engine := &Engine{Management: client, Store: store, Now: func() time.Time { return now }}
			entry := status.Consumer{Condition: "BootstrapRequired", Expiry: now.Add(time.Hour), LastSuccess: now.Add(-time.Hour)}
			if mode == "latched" {
				entry.Condition = "SafetyStopped"
				entry.StopLatched = true
			}
			if err := engine.save(context.Background(), consumer.ID, &entry); err != nil {
				t.Fatal(err)
			}
			var acquisition error
			if mode == "issuer-rejected" {
				acquisition = provider.Auth
			}
			err := engine.consumer(context.Background(), cluster, consumer, "generation", entry, nil, provider.IssuerCredential{}, acquisition, mode != "disabled")
			if (err == nil) != (mode == "recovered" || mode == "latched" || mode == "disabled") {
				t.Fatalf("unexpected recovery result: %v", err)
			}
			snapshot, err := store.Read(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			actual := snapshot.Consumers[consumer.ID]
			want := "BootstrapRequired"
			if mode == "recovered" {
				want = "Healthy"
			}
			if mode == "latched" {
				want = "SafetyStopped"
			}
			if actual.Condition != want || !actual.Expiry.Equal(entry.Expiry) || !actual.LastSuccess.Equal(entry.LastSuccess) || actual.Intent != nil || actual.StopLatched != (mode == "latched") {
				t.Fatalf("unexpected durable state: %+v", actual)
			}
			for _, a := range client.Actions() {
				if a.GetVerb() == "patch" || (a.GetResource().Resource == "secrets" && a.GetVerb() != "get") {
					t.Fatal("validation mutated credential or deployment")
				}
			}
			if requests != 0 {
				t.Fatal("validation issued a token or performed another request")
			}
		})
	}
}
