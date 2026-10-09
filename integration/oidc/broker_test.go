package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	auth "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	kt "k8s.io/client-go/testing"
)

func fixture(t *testing.T, mode string) (*Broker, *int) {
	t.Helper()
	client := fake.NewSimpleClientset()
	calls := 0
	client.PrependReactor("create", "tokenreviews", func(action kt.Action) (bool, runtime.Object, error) {
		calls++
		input := action.(kt.CreateAction).GetObject().(*auth.TokenReview)
		if input.Spec.Token != "synthetic-subject" || len(input.Spec.Audiences) != 1 || input.Spec.Audiences[0] != "fixture-broker" {
			t.Fatal("subject was not reviewed with the exact broker audience")
		}
		result := &auth.TokenReview{Status: auth.TokenReviewStatus{Authenticated: true, Audiences: []string{"fixture-broker"}, User: auth.UserInfo{Username: "system:serviceaccount:fixture:controller", UID: "subject-uid", Groups: []string{"system:authenticated"}}}}
		switch mode {
		case "uid":
			result.Status.User.UID = "replacement-uid"
		case "privileged":
			result.Status.User.Groups = []string{"system:masters"}
		case "audience":
			result.Status.Audiences = []string{"another-audience"}
		case "revoked":
			result.Status.Authenticated = false
		}
		return true, result, nil
	})
	b, err := New(Settings{Issuer: "https://fixture-broker", ClientID: "fixture-client", ClientSecret: "synthetic-client-secret", SubjectAudience: "fixture-broker", ChildAudience: "fixture-child", SubjectUsername: "system:serviceaccount:fixture:controller", SubjectUID: "subject-uid", SubjectGroups: []string{"system:authenticated"}, Management: client})
	if err != nil {
		t.Fatal("fixture setup failed")
	}
	return b, &calls
}

func exchange(b *Broker, modify func(url.Values), secret string) *httptest.ResponseRecorder {
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {"synthetic-subject"}, "subject_token_type": {"urn:ietf:params:oauth:token-type:jwt"}, "requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "audience": {"fixture-child"}, "scope": {"issue"}}
	if modify != nil {
		modify(form)
	}
	r := httptest.NewRequest(http.MethodPost, "https://fixture-broker/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth("fixture-client", secret)
	w := httptest.NewRecorder()
	b.ServeHTTP(w, r)
	return w
}

func publicKeys(t *testing.T, b *Broker) jose.JSONWebKeySet {
	t.Helper()
	w := httptest.NewRecorder()
	b.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://fixture-broker/jwks", nil))
	var result jose.JSONWebKeySet
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &result) != nil {
		t.Fatal("fixture JWKS unavailable")
	}
	for _, key := range result.Keys {
		if !key.IsPublic() {
			t.Fatal("fixture JWKS exposed private signing material")
		}
	}
	return result
}

func issued(t *testing.T, b *Broker) string {
	t.Helper()
	w := exchange(b, nil, "synthetic-client-secret")
	var response struct {
		Token string `json:"access_token"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Token == "" {
		t.Fatal("fixture did not issue a token")
	}
	return response.Token
}

func TestExchangeRequiresActualSubjectReviewAndSignsRestrictedClaims(t *testing.T) {
	b, calls := fixture(t, "")
	token := issued(t, b)
	if *calls != 1 {
		t.Fatal("subject review missing")
	}
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal("issued JWT malformed")
	}
	var claims jwt.Claims
	var groups struct {
		Groups []string `json:"groups"`
	}
	keys := publicKeys(t, b)
	if len(keys.Keys) != 1 || parsed.Claims(keys.Keys[0].Key, &claims, &groups) != nil || claims.Validate(jwt.Expected{Issuer: "https://fixture-broker", Subject: "issuer", AnyAudience: jwt.Audience{"fixture-child"}, Time: time.Now()}) != nil || len(groups.Groups) != 1 || groups.Groups[0] != "issuers" {
		t.Fatal("signed issuer claims do not match the restricted fixture")
	}
}

func TestExchangeRejectsUntrustedSubjectAndProtocol(t *testing.T) {
	for _, mode := range []string{"uid", "privileged", "audience", "revoked", "client", "scope", "duplicate", "extra"} {
		t.Run(mode, func(t *testing.T) {
			b, _ := fixture(t, mode)
			secret := "synthetic-client-secret"
			if mode == "client" {
				secret = "synthetic-wrong-secret"
			}
			response := exchange(b, func(form url.Values) {
				switch mode {
				case "scope":
					form.Set("scope", "admin")
				case "duplicate":
					form.Add("audience", "another-child")
				case "extra":
					form.Set("unexpected", "value")
				}
			}, secret)
			if response.Code == http.StatusOK || strings.Contains(response.Body.String(), "synthetic-") || strings.Contains(response.Body.String(), "access_token") {
				t.Fatal("untrusted exchange succeeded or exposed credential material")
			}
		})
	}
}

func TestKeyAndClientRotationAndSubjectRevocation(t *testing.T) {
	b, _ := fixture(t, "")
	old := publicKeys(t, b).Keys[0]
	if b.RotateKey(true) != nil || len(publicKeys(t, b).Keys) != 2 {
		t.Fatal("overlapping JWKS rotation failed")
	}
	if b.RotateKey(false) != nil {
		t.Fatal("JWKS predecessor removal failed")
	}
	keys := publicKeys(t, b)
	if len(keys.Keys) != 1 || keys.Keys[0].KeyID == old.KeyID {
		t.Fatal("old signing key remained published")
	}
	if b.ReplaceClientSecret("replacement-synthetic-secret") != nil || exchange(b, nil, "synthetic-client-secret").Code != http.StatusUnauthorized || exchange(b, nil, "replacement-synthetic-secret").Code != http.StatusOK {
		t.Fatal("client secret rotation failed")
	}
	b.RevokeSubject()
	if exchange(b, nil, "replacement-synthetic-secret").Code != http.StatusUnauthorized {
		t.Fatal("revoked subject still exchanged")
	}
}
