package provider

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/testutil"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

const uid = "00000000-0000-0000-0000-000000000001"

func TestOAuthExchange(t *testing.T) {
	now := time.Unix(2000000000, 0)
	for _, mode := range []string{"valid", "duplicate", "ttl", "scope", "refresh", "denied", "redirect", "oversize", "audience"} {
		t.Run(mode, func(t *testing.T) {
			var calls int
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				user, pass, ok := r.BasicAuth()
				if !ok || user != "test-client" || pass != "synthetic-canary" {
					t.Error("incorrect client authentication")
				}
				if r.ParseForm() != nil || r.Form.Get("grant_type") != tokenExchange || r.Form.Get("audience") != "child-api" || r.Form.Get("scope") != "issue" || r.Form.Get("subject_token") == "" {
					t.Error("incorrect exchange form")
				}
				if mode == "denied" {
					w.WriteHeader(401)
					return
				}
				if mode == "redirect" {
					w.Header().Set("Location", "https://example.invalid/")
					w.WriteHeader(302)
					return
				}
				if mode == "duplicate" {
					_, _ = w.Write([]byte(`{"access_token":"synthetic-canary","access_token":"duplicate"}`))
					return
				}
				if mode == "oversize" {
					_, _ = w.Write([]byte(strings.Repeat(" ", 65537)))
					return
				}
				audience := "child-api"
				if mode == "audience" {
					audience = "wrong"
				}
				response := map[string]any{"access_token": testutil.Token("machine-issuer", "", "", "", []string{audience}, now, 1800), "token_type": "Bearer", "issued_token_type": accessToken, "expires_in": 1800, "scope": "issue"}
				if mode == "ttl" {
					response["expires_in"] = 1
				}
				if mode == "scope" {
					response["scope"] = "admin"
				}
				if mode == "refresh" {
					response["refresh_token"] = "synthetic-canary"
				}
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			trust := &core.Secret{ObjectMeta: meta.ObjectMeta{Namespace: "identity", Name: "trust", UID: types.UID(uid)}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"ca.crt": ca, "api-ca.crt": ca}}
			secret := &core.Secret{ObjectMeta: meta.ObjectMeta{Namespace: "identity", Name: "client", UID: types.UID(uid)}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"client-secret": []byte("synthetic-canary")}}
			c := config.Cluster{CASHA256: credential.Hash(ca), Provider: config.Provider{Type: "OAuthTokenExchange", TokenEndpoint: server.URL, TrustSecret: &config.Ref{Namespace: "identity", Name: "trust", UID: uid}, ClientSecret: &config.Ref{Namespace: "identity", Name: "client", UID: uid}, ClientID: "test-client", SubjectTokenVolume: "broker", SubjectTokenAudience: "broker", Audience: "child-api", Scopes: []string{"issue"}, AcceptedMinSeconds: 600, AcceptedMaxSeconds: 3600}}
			reads := 0
			p := OAuthTokenExchange{Management: fake.NewClientset(trust, secret), Now: func() time.Time { return now }, Subject: func(string) ([]byte, error) {
				reads++
				return []byte(testutil.Token("system:serviceaccount:management:requestor", "", "", "", []string{"broker"}, now, 3600)), nil
			}}
			result, err := p.Acquire(context.Background(), c)
			if mode == "valid" {
				if err != nil || result.Bearer == "" || result.Expires.Unix() != now.Unix()+1800 {
					t.Fatal("valid exchange rejected")
				}
				_, err = p.Acquire(context.Background(), c)
				if err != nil || reads != 2 || calls != 2 {
					t.Fatal("subject was cached")
				}
			} else if err == nil {
				t.Fatal("unsafe exchange accepted")
			}
			if err != nil && strings.Contains(err.Error(), "canary") {
				t.Fatal("credential leaked")
			}
		})
	}
}
