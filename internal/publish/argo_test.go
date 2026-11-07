package publish

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/issue"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/testutil"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func boundToken(ttl int64) string {
	token := testutil.Token("system:serviceaccount:identity:gitops", "identity", "gitops", "sa-uid", []string{"api"}, time.Unix(2000000000, 0), ttl)
	parts := strings.Split(token, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c map[string]any
	json.Unmarshal(payload, &c)
	c["kubernetes.io"].(map[string]any)["secret"] = map[string]string{"name": "lease", "uid": "lease-uid"}
	payload, _ = json.Marshal(c)
	parts[1] = base64.RawURLEncoding.EncodeToString(payload)
	return strings.Join(parts, ".")
}
func argoFixture() (config.Cluster, config.Consumer, *core.Secret) {
	c := config.Cluster{Endpoint: "https://api.example.invalid:6443", CASHA256: credential.Hash([]byte("public-ca")), IdentityNamespace: "identity", Audiences: []string{"api"}}
	consumer := config.Consumer{ID: "gitops", ServiceAccount: config.ServiceAccount{Name: "gitops", UID: "sa-uid"}, Secret: config.Ref{Name: "output", Namespace: "management", UID: "secret-uid"}, GitOps: &config.GitOps{Name: "target", Project: "project", Namespace: "identity", ConfigMap: "probe", EnrollmentUID: "enrollment-uid", BoundSecret: config.Ref{Name: "lease", UID: "lease-uid", Namespace: "identity"}}}
	cfg := argoConfig{BearerToken: boundToken(1800)}
	cfg.TLS.CA = []byte("public-ca")
	data, _ := json.Marshal(cfg)
	s := &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "output", Namespace: "management", UID: types.UID("secret-uid"), ResourceVersion: "10", Labels: map[string]string{"argocd.argoproj.io/secret-type": "cluster"}, Annotations: map[string]string{Owner: "gitops", Enrollment: "enrollment-uid", "retained": "value"}}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"name": []byte("target"), "server": []byte(c.Endpoint), "namespaces": []byte("identity"), "clusterResources": []byte("false"), "project": []byte("project"), "config": data}}
	return c, consumer, s
}
func TestArgoPublication(t *testing.T) {
	c, consumer, s := argoFixture()
	client := fake.NewClientset(s.DeepCopy())
	candidate := issue.Candidate{Token: boundToken(3600), CA: []byte("public-ca"), Expires: time.Unix(2000003600, 0)}
	if err := Commit(context.Background(), client, c, consumer, s, candidate, "generation"); err != nil {
		t.Fatal(err)
	}
	got, err := Read(context.Background(), client, consumer)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range s.Data {
		if k != "config" && string(got.Data[k]) != string(v) {
			t.Fatal("changed destination binding")
		}
	}
	if got.UID != s.UID || got.Annotations["retained"] != "value" {
		t.Fatal("changed identity")
	}
	if err := Commit(context.Background(), client, c, consumer, got, candidate, "generation"); err != provider.Conflict {
		t.Fatal("non-monotonic publication")
	}
	got.ResourceVersion = "11"
	client.CoreV1().Secrets(got.Namespace).Update(context.Background(), got, meta.UpdateOptions{})
	if err := Commit(context.Background(), client, c, consumer, s, issue.Candidate{Token: boundToken(7200), CA: []byte("public-ca"), Expires: time.Unix(2000007200, 0)}, "generation"); err == nil {
		t.Fatal("stale resourceVersion accepted")
	}
}
func TestArgoRejectsBindingDriftBeforeWrite(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*core.Secret)
	}{
		{"project", func(s *core.Secret) { s.Data["project"] = []byte("other") }},
		{"server", func(s *core.Secret) { s.Data["server"] = []byte("https://other.example.invalid") }},
		{"owner", func(s *core.Secret) { s.Annotations[Owner] = "other" }},
		{"uid", func(s *core.Secret) { s.UID = "other" }},
		{"enrollment", func(s *core.Secret) { s.Annotations[Enrollment] = "other" }},
		{"exec", func(s *core.Secret) {
			var cfg map[string]any
			json.Unmarshal(s.Data["config"], &cfg)
			cfg["execProviderConfig"] = map[string]any{}
			s.Data["config"], _ = json.Marshal(cfg)
		}},
		{"duplicate", func(s *core.Secret) {
			s.Data["config"] = []byte(`{"bearerToken":"one","bearerToken":"two","tlsClientConfig":{}}`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, consumer, s := argoFixture()
			tc.mutate(s)
			client := fake.NewClientset(s)
			if err := Commit(context.Background(), client, c, consumer, s, issue.Candidate{Token: boundToken(3600), CA: []byte("public-ca"), Expires: time.Unix(2000003600, 0)}, "generation"); err != provider.Trust {
				t.Fatal("drift accepted", err)
			}
			if len(client.Actions()) != 0 {
				t.Fatal("unexpected API call")
			}
		})
	}
}
