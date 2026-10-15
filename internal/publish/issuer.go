package publish

import (
	"context"
	"crypto/subtle"
	"encoding/json"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/issue"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// CommitIssuer preserves trust and metadata; a stale leader/operator can never overwrite a successor.
func CommitIssuer(ctx context.Context, client kubernetes.Interface, c config.Cluster, previous *core.Secret, candidate issue.Candidate) error {
	ref, account := c.Provider.Secret, c.Provider.ServiceAccount
	if c.Provider.Type != "SecretIssuer" || c.Provider.Renewal == nil || ref == nil || account == nil || previous == nil || string(previous.UID) != ref.UID || previous.ResourceVersion == "" || previous.Type != core.SecretTypeOpaque || len(previous.Data) != 2 || (previous.Immutable != nil && *previous.Immutable) ||
		previous.Name != ref.Name || previous.Namespace != ref.Namespace || credential.Hash(previous.Data["ca.crt"]) != c.CASHA256 || subtle.ConstantTimeCompare(previous.Data["ca.crt"], candidate.CA) != 1 {
		return provider.Trust
	}
	old, err := credential.Parse(string(previous.Data["token"]))
	if err != nil {
		return provider.Auth
	}
	claims, err := credential.Parse(candidate.Token)
	if err != nil || claims.Subject != c.ExpectedIssuer.Username || claims.Kubernetes.Namespace != c.IdentityNamespace || claims.Kubernetes.ServiceAccount.Name != account.Name || claims.Kubernetes.ServiceAccount.UID != account.UID ||
		!credential.SameSet(claims.Audience, c.Audiences) || candidate.Expires.Unix() != claims.Expires || claims.Expires <= old.Expires {
		return provider.Auth
	}
	body, err := json.Marshal([]map[string]any{
		{"op": "test", "path": "/metadata/uid", "value": ref.UID},
		{"op": "test", "path": "/metadata/resourceVersion", "value": previous.ResourceVersion},
		{"op": "replace", "path": "/data/token", "value": []byte(candidate.Token)},
	})
	if err != nil {
		return provider.Trust
	}
	if _, err = client.CoreV1().Secrets(ref.Namespace).Patch(ctx, ref.Name, types.JSONPatchType, body, meta.PatchOptions{}); err != nil {
		return provider.Classify(err)
	}
	committed, err := provider.ReadSecret(ctx, client, *ref, "ca.crt", "token")
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(committed.Data["token"], []byte(candidate.Token)) != 1 || subtle.ConstantTimeCompare(committed.Data["ca.crt"], candidate.CA) != 1 {
		return provider.Conflict
	}
	return nil
}
