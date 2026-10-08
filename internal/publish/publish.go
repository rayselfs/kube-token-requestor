// Package publish owns only named output credentials; all writes use UID/RV preconditions.
package publish

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/issue"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

const Owner = "token-requestor.io/consumer"
const Expiry = "token-requestor.io/expires-at"
const Generation = "token-requestor.io/generation"

func Read(ctx context.Context, client kubernetes.Interface, consumer config.Consumer) (*core.Secret, error) {
	s, err := client.CoreV1().Secrets(consumer.Secret.Namespace).Get(ctx, consumer.Secret.Name, meta.GetOptions{})
	if err != nil {
		return nil, provider.Classify(err)
	}
	if string(s.UID) != consumer.Secret.UID || s.Type != core.SecretTypeOpaque || (s.Immutable != nil && *s.Immutable) || len(s.Data) != 2 ||
		s.Data["ca.crt"] == nil || s.Data["token"] == nil || s.Annotations[Owner] != consumer.ID {
		return nil, provider.Trust
	}
	return s, nil
}

func StoredExpiry(secret *core.Secret, c config.Cluster, consumer config.Consumer) time.Time {
	claims, err := credential.Parse(string(secret.Data["token"]))
	if err != nil || credential.Hash(secret.Data["ca.crt"]) != c.CASHA256 || claims.Subject != "system:serviceaccount:"+c.IdentityNamespace+":"+consumer.ServiceAccount.Name ||
		claims.Kubernetes.ServiceAccount.UID != consumer.ServiceAccount.UID || !credential.SameSet(claims.Audience, c.Audiences) {
		return time.Time{}
	}
	return time.Unix(claims.Expires, 0)
}

func Commit(ctx context.Context, client kubernetes.Interface, c config.Cluster, consumer config.Consumer, previous *core.Secret, candidate issue.Candidate, generation string) error {
	if previous == nil || string(previous.UID) != consumer.Secret.UID || previous.Annotations[Owner] != consumer.ID || credential.Hash(previous.Data["ca.crt"]) != c.CASHA256 {
		return provider.Trust
	}
	claims, err := credential.Parse(candidate.Token)
	if err != nil || claims.Subject != "system:serviceaccount:"+c.IdentityNamespace+":"+consumer.ServiceAccount.Name || claims.Kubernetes.ServiceAccount.UID != consumer.ServiceAccount.UID ||
		!credential.SameSet(claims.Audience, c.Audiences) || candidate.Expires.Unix() != claims.Expires {
		return provider.Trust
	}
	if !candidate.Expires.After(StoredExpiry(previous, c, consumer)) {
		return provider.Conflict
	}
	annotations := map[string]string{}
	for key, value := range previous.Annotations {
		annotations[key] = value
	}
	annotations[Expiry], annotations[Generation] = candidate.Expires.UTC().Format(time.RFC3339), generation
	patch := []map[string]any{
		{"op": "test", "path": "/metadata/uid", "value": consumer.Secret.UID},
		{"op": "test", "path": "/metadata/resourceVersion", "value": previous.ResourceVersion},
		{"op": "replace", "path": "/data/token", "value": []byte(candidate.Token)},
		{"op": "add", "path": "/metadata/annotations", "value": annotations},
	}
	if subtle.ConstantTimeCompare(previous.Data["ca.crt"], candidate.CA) != 1 {
		return provider.Trust
	}
	body, err := json.Marshal(patch)
	if err != nil {
		return provider.Trust
	}
	_, err = client.CoreV1().Secrets(consumer.Secret.Namespace).Patch(ctx, consumer.Secret.Name, types.JSONPatchType, body, meta.PatchOptions{})
	if err != nil {
		return provider.Classify(err)
	}
	committed, err := Read(ctx, client, consumer)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(committed.Data["token"], []byte(candidate.Token)) != 1 || committed.Annotations[Generation] != generation ||
		!StoredExpiry(committed, c, consumer).Equal(candidate.Expires) {
		return provider.Conflict
	}
	return nil
}
