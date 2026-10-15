package reconcile

import (
	"context"
	"crypto/subtle"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/issue"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/publish"
	"k8s.io/client-go/kubernetes"
)

// Source renewal runs on the elected cluster queue independently of consumer deadlines.
// A crash before CAS leaves the predecessor valid; after CAS the next leader reads the successor.
func (e *Engine) renewIssuer(ctx context.Context, c config.Cluster, generation string, client kubernetes.Interface, identity provider.IssuerCredential) (result kubernetes.Interface, renewed provider.IssuerCredential, resultErr error) {
	policy := c.Provider.Renewal
	if policy == nil || identity.Expires.After(e.Now().Add(time.Duration(policy.RenewBeforeSeconds)*time.Second)) {
		return client, identity, nil
	}
	if c.Provider.Type != "SecretIssuer" || e.Current == nil {
		return nil, identity, provider.Trust
	}
	defer func() {
		if e.Event != nil {
			outcome := "Healthy"
			if resultErr != nil {
				outcome = provider.Classify(resultErr).Error()
			}
			e.Event("issuer", c.ID, "", outcome)
		}
	}()
	previous, err := provider.ReadSecret(ctx, e.Management, *c.Provider.Secret, "ca.crt", "token")
	if err != nil {
		return nil, identity, err
	}
	if subtle.ConstantTimeCompare(previous.Data["token"], []byte(identity.Bearer)) != 1 || subtle.ConstantTimeCompare(previous.Data["ca.crt"], identity.CA) != 1 {
		return nil, identity, provider.Conflict
	}
	if err = e.Current(ctx, generation); err != nil {
		return nil, identity, err
	}
	candidate, err := issue.RequestIssuer(ctx, client, c, identity.CA, e.Now())
	if err != nil {
		return nil, identity, err
	}
	if err = e.Current(ctx, generation); err != nil {
		return nil, identity, err
	}
	if err = publish.CommitIssuer(ctx, e.Management, c, previous, candidate); err != nil {
		return nil, identity, err
	}
	identity = provider.IssuerCredential{Bearer: candidate.Token, CA: candidate.CA, Expires: candidate.Expires}
	client, err = issue.Client(c.Endpoint, identity)
	return client, identity, err
}
