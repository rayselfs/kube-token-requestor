package publish

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/issue"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/safejson"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

const Enrollment = "token-requestor.io/enrollment-uid"

type argoConfig struct {
	BearerToken string `json:"bearerToken"`
	TLS         struct {
		Insecure bool   `json:"insecure"`
		CA       []byte `json:"caData"`
	} `json:"tlsClientConfig"`
}

func readArgo(s *core.Secret, consumer config.Consumer) (*core.Secret, error) {
	g := consumer.GitOps
	if s == nil || g == nil || string(s.UID) != consumer.Secret.UID || s.Type != core.SecretTypeOpaque || (s.Immutable != nil && *s.Immutable) || len(s.Data) != 6 || s.Annotations[Owner] != consumer.ID || s.Annotations[Enrollment] != g.EnrollmentUID || s.Labels["argocd.argoproj.io/secret-type"] != "cluster" {
		return nil, provider.Trust
	}
	for k, v := range map[string]string{"name": g.Name, "project": g.Project, "namespaces": g.Namespace, "clusterResources": "false"} {
		if string(s.Data[k]) != v {
			return nil, provider.Trust
		}
	}
	if !config.APIEndpoint(string(s.Data["server"])) {
		return nil, provider.Trust
	}
	if _, err := decodeArgo(s.Data["config"]); err != nil {
		return nil, err
	}
	return s, nil
}

func decodeArgo(data []byte) (argoConfig, error) {
	var cfg argoConfig
	var fields map[string]json.RawMessage
	if safejson.Decode(data, &fields, 65536) != nil || len(fields) != 2 || fields["bearerToken"] == nil || fields["tlsClientConfig"] == nil {
		return cfg, provider.Trust
	}
	var tls map[string]json.RawMessage
	if safejson.Decode(fields["tlsClientConfig"], &tls, 32768) != nil || len(tls) != 2 || tls["insecure"] == nil || tls["caData"] == nil || string(bytes.TrimSpace(tls["insecure"])) != "false" {
		return cfg, provider.Trust
	}
	if safejson.Decode(data, &cfg, 65536) != nil || cfg.TLS.Insecure || len(cfg.TLS.CA) == 0 || cfg.BearerToken == "" {
		return cfg, provider.Trust
	}
	return cfg, nil
}

func argoMaterial(s *core.Secret, c config.Cluster, consumer config.Consumer) (provider.IssuerCredential, error) {
	if _, err := readArgo(s, consumer); err != nil {
		return provider.IssuerCredential{}, err
	}
	cfg, err := decodeArgo(s.Data["config"])
	if err != nil || string(s.Data["server"]) != c.Endpoint || credential.Hash(cfg.TLS.CA) != c.CASHA256 {
		return provider.IssuerCredential{}, provider.Trust
	}
	return provider.IssuerCredential{Bearer: cfg.BearerToken, CA: cfg.TLS.CA}, nil
}

func commitArgo(ctx context.Context, client kubernetes.Interface, c config.Cluster, consumer config.Consumer, previous *core.Secret, candidate issue.Candidate, generation string) error {
	old, err := argoMaterial(previous, c, consumer)
	if err != nil || subtle.ConstantTimeCompare(old.CA, candidate.CA) != 1 {
		return provider.Trust
	}
	claims, err := credential.Parse(candidate.Token)
	if err != nil || claims.Subject != "system:serviceaccount:"+c.IdentityNamespace+":"+consumer.ServiceAccount.Name || claims.Kubernetes.ServiceAccount.UID != consumer.ServiceAccount.UID || !credential.SameSet(claims.Audience, c.Audiences) || !issue.BoundClaims(claims, consumer) || claims.Expires != candidate.Expires.Unix() {
		return provider.Trust
	}
	if !candidate.Expires.After(StoredExpiry(previous, c, consumer)) {
		return provider.Conflict
	}
	cfg, _ := decodeArgo(previous.Data["config"])
	cfg.BearerToken = candidate.Token
	encoded, err := json.Marshal(cfg)
	if err != nil {
		return provider.Trust
	}
	annotations := map[string]string{}
	for k, v := range previous.Annotations {
		annotations[k] = v
	}
	annotations[Expiry], annotations[Generation] = candidate.Expires.UTC().Format(time.RFC3339), generation
	patch := []map[string]any{
		{"op": "test", "path": "/metadata/uid", "value": consumer.Secret.UID},
		{"op": "test", "path": "/metadata/resourceVersion", "value": previous.ResourceVersion},
		{"op": "replace", "path": "/data/config", "value": encoded},
		{"op": "add", "path": "/metadata/annotations", "value": annotations},
	}
	body, _ := json.Marshal(patch)
	if _, err = client.CoreV1().Secrets(consumer.Secret.Namespace).Patch(ctx, consumer.Secret.Name, types.JSONPatchType, body, meta.PatchOptions{}); err != nil {
		return provider.Classify(err)
	}
	committed, err := Read(ctx, client, consumer)
	if err != nil {
		return err
	}
	actual, err := argoMaterial(committed, c, consumer)
	if err != nil || subtle.ConstantTimeCompare([]byte(actual.Bearer), []byte(candidate.Token)) != 1 || committed.Annotations[Generation] != generation || !StoredExpiry(committed, c, consumer).Equal(candidate.Expires) {
		return provider.Conflict
	}
	return nil
}
