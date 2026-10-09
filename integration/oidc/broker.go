// Package oidc provides a synthetic, in-memory exchange/JWKS fixture, not a deployable broker.
package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	auth "k8s.io/api/authentication/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var rejected = errors.New("synthetic exchange rejected")

type Settings struct {
	Issuer, ClientID, ClientSecret, SubjectAudience, ChildAudience string
	SubjectUsername, SubjectUID                                    string
	SubjectGroups                                                  []string
	Management                                                     kubernetes.Interface
}

type Broker struct {
	mu                sync.RWMutex
	settings          Settings
	signer            jose.Signer
	keys              []jose.JSONWebKey
	subjectLive       bool
	discoveryRequests atomic.Uint64
	jwksRequests      atomic.Uint64
	projected         map[string]projectionSample
	rejectNext        bool
	rejectedHash      [32]byte
	rejectedCalls     uint64
}

type projectionSample struct {
	hash                      [32]byte
	Count                     int
	FirstExpiry, LatestExpiry int64
}

// BindProjectedSubject enrolls the Helm-created account in this synthetic fixture only.
func (b *Broker) BindProjectedSubject(username, uid string) error {
	if username == "" || uid == "" {
		return rejected
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.SubjectUsername, b.settings.SubjectUID = username, uid
	b.projected = map[string]projectionSample{}
	b.rejectNext, b.rejectedHash, b.rejectedCalls = false, [32]byte{}, 0
	return nil
}

func (b *Broker) projectedSample(uid string) projectionSample {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.projected[uid]
}

func (b *Broker) recordProjection(token string) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return
	}
	var claims struct {
		Expires    int64 `json:"exp"`
		Kubernetes struct {
			Pod struct {
				UID string `json:"uid"`
			} `json:"pod"`
		} `json:"kubernetes.io"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Kubernetes.Pod.UID == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.projected == nil {
		return
	}
	sample := b.projected[claims.Kubernetes.Pod.UID]
	hash := sha256.Sum256([]byte(token))
	if sample.Count == 0 {
		sample.FirstExpiry = claims.Expires
	}
	if hash != sample.hash {
		sample.Count++
		sample.hash, sample.LatestExpiry = hash, claims.Expires
	}
	b.projected[claims.Kubernetes.Pod.UID] = sample
}

// rejectProjectedOnce holds one reviewed subject hash until kubelet replaces it.
// Neither the token nor its private fingerprint leaves this in-memory fixture.
func (b *Broker) rejectProjectedOnce() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rejectNext = true
}
func (b *Broker) rejectReviewedSubject(token string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	hash := sha256.Sum256([]byte(token))
	if b.rejectNext {
		b.rejectedHash = hash
		b.rejectNext = false
	}
	if b.rejectedHash == hash {
		b.rejectedCalls++
		return true
	}
	return false
}
func (b *Broker) rejectionCount() uint64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.rejectedCalls
}

func New(settings Settings) (*Broker, error) {
	u, err := url.Parse(settings.Issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || settings.Management == nil ||
		settings.ClientID == "" || settings.ClientSecret == "" || settings.SubjectAudience == "" || settings.ChildAudience == "" || settings.SubjectUsername == "" || settings.SubjectUID == "" || len(settings.SubjectGroups) == 0 {
		return nil, rejected
	}
	b := &Broker{settings: settings, subjectLive: true}
	b.settings.SubjectGroups = append([]string(nil), settings.SubjectGroups...)
	if err := b.RotateKey(false); err != nil {
		return nil, err
	}
	return b, nil
}

// BindReviewer is a fixture bootstrap step after the fresh API and subject account exist.
func (b *Broker) BindReviewer(client kubernetes.Interface, subjectUID string) error {
	if client == nil || subjectUID == "" {
		return rejected
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.Management, b.settings.SubjectUID = client, subjectUID
	return nil
}

// RotateKey can retain the predecessor during overlap or remove it to test actual API rejection.
func (b *Broker) RotateKey(retain bool) error {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return rejected
	}
	public := jose.JSONWebKey{Key: &private.PublicKey, Algorithm: string(jose.RS256), Use: "sig"}
	thumbprint, err := public.Thumbprint(crypto.SHA256)
	if err != nil {
		return rejected
	}
	public.KeyID = base64.RawURLEncoding.EncodeToString(thumbprint)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: private}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", public.KeyID))
	if err != nil {
		return rejected
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !retain {
		b.keys = nil
	}
	b.keys = append(b.keys, public)
	b.signer = signer
	return nil
}

func (b *Broker) ReplaceClientSecret(secret string) error {
	if secret == "" {
		return rejected
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.ClientSecret = secret
	return nil
}

func (b *Broker) RevokeSubject() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subjectLive = false
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(value)
}

func (b *Broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		http.Error(w, rejected.Error(), http.StatusBadRequest)
		return
	}
	b.mu.RLock()
	settings, signer, live := b.settings, b.signer, b.subjectLive
	keys := append([]jose.JSONWebKey(nil), b.keys...)
	b.mu.RUnlock()
	if r.Method == http.MethodGet && r.URL.Path == "/.well-known/openid-configuration" {
		b.discoveryRequests.Add(1)
		writeJSON(w, map[string]any{"issuer": settings.Issuer, "jwks_uri": settings.Issuer + "/jwks", "response_types_supported": []string{"id_token"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}})
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/jwks" {
		b.jwksRequests.Add(1)
		writeJSON(w, jose.JSONWebKeySet{Keys: keys})
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/token" {
		http.Error(w, rejected.Error(), http.StatusNotFound)
		return
	}
	id, secret, ok := r.BasicAuth()
	id, idErr := url.QueryUnescape(id)
	secret, secretErr := url.QueryUnescape(secret)
	if !ok || idErr != nil || secretErr != nil || id != settings.ClientID || subtle.ConstantTimeCompare([]byte(secret), []byte(settings.ClientSecret)) != 1 || !live {
		http.Error(w, rejected.Error(), http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32768)
	if r.ParseForm() != nil || len(r.PostForm) != 6 {
		http.Error(w, rejected.Error(), http.StatusBadRequest)
		return
	}
	expected := map[string]string{"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token_type": "urn:ietf:params:oauth:token-type:jwt", "requested_token_type": "urn:ietf:params:oauth:token-type:access_token", "audience": settings.ChildAudience, "scope": "issue"}
	for field, value := range expected {
		if len(r.PostForm[field]) != 1 || r.PostForm.Get(field) != value {
			http.Error(w, rejected.Error(), http.StatusBadRequest)
			return
		}
	}
	if len(r.PostForm["subject_token"]) != 1 || r.PostForm.Get("subject_token") == "" {
		http.Error(w, rejected.Error(), http.StatusBadRequest)
		return
	}
	review, err := settings.Management.AuthenticationV1().TokenReviews().Create(r.Context(), &auth.TokenReview{Spec: auth.TokenReviewSpec{Token: r.PostForm.Get("subject_token"), Audiences: []string{settings.SubjectAudience}}}, meta.CreateOptions{})
	if err != nil || !review.Status.Authenticated || review.Status.Error != "" || review.Status.User.Username != settings.SubjectUsername || review.Status.User.UID != settings.SubjectUID || !credential.SameSet(review.Status.User.Groups, settings.SubjectGroups) || len(review.Status.Audiences) != 1 || review.Status.Audiences[0] != settings.SubjectAudience {
		http.Error(w, rejected.Error(), http.StatusUnauthorized)
		return
	}
	b.recordProjection(r.PostForm.Get("subject_token"))
	if b.rejectReviewedSubject(r.PostForm.Get("subject_token")) {
		http.Error(w, rejected.Error(), http.StatusUnauthorized)
		return
	}
	now := time.Now()
	token, err := jwt.Signed(signer).Claims(jwt.Claims{Issuer: settings.Issuer, Subject: "issuer", Audience: jwt.Audience{settings.ChildAudience}, IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(10 * time.Minute))}).Claims(struct {
		Groups []string `json:"groups"`
	}{Groups: []string{"issuers"}}).Serialize()
	if err != nil {
		http.Error(w, rejected.Error(), http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"access_token": token, "token_type": "Bearer", "issued_token_type": "urn:ietf:params:oauth:token-type:access_token", "expires_in": 600, "scope": "issue"})
}
