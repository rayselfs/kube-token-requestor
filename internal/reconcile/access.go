package reconcile

import (
	"context"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/issue"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/publish"
	"github.com/rayselfs/kube-token-requestor/internal/status"
	"k8s.io/client-go/kubernetes"
)

// credentialOnly publishes without scaling workloads. Consumer admission and revocation remain external.
func (e *Engine) credentialOnly(ctx context.Context, c config.Cluster, consumer config.Consumer, generation string, entry status.Consumer, issuer kubernetes.Interface, identity provider.IssuerCredential, acquisition error, enabled bool) error {
	blocked, disabled := "AccessBlocked", "AccessDisabled"
	if consumer.IsGitOps() {
		blocked, disabled = "GitOpsBlocked", "GitOpsDisabled"
	}
	output, err := publish.Read(ctx, e.Management, consumer)
	if err != nil {
		return err
	}
	expires := publish.StoredExpiry(output, c, consumer)
	previousExpiry := entry.Expiry
	entry.Expiry = expires
	e.mu.Lock()
	if e.expiries == nil {
		e.expiries = map[string]time.Time{}
	}
	e.expiries[consumer.ID] = expires
	e.mu.Unlock()
	unsafe := !expires.After(e.Now().Add(time.Duration(c.Lifetime.StopBeforeSeconds+c.Lifetime.ClockSkewSeconds) * time.Second))
	if unsafe || entry.Intent != nil {
		e.mu.Lock()
		delete(e.expiries, consumer.ID)
		e.mu.Unlock()
		entry.StopLatched, entry.Condition, entry.Acknowledgement = true, blocked, output.Annotations[Acknowledge]
		if err := e.save(ctx, consumer.ID, &entry); err != nil {
			return err
		}
		return provider.Trust
	}
	// Recovery requires an independently supplied valid replacement and a new operator nonce.
	if entry.StopLatched {
		ack := output.Annotations[Acknowledge]
		if !enabled || !expires.After(previousExpiry) || !acknowledgement.MatchString(ack) || ack == entry.Acknowledgement {
			return provider.Trust
		}
		material, err := publish.Material(output, c, consumer)
		if err != nil {
			return err
		}
		client, err := issue.Client(c.Endpoint, material)
		if err != nil {
			return err
		}
		if err := issue.ValidateConsumer(ctx, client, c, consumer); err != nil {
			return err
		}
		entry.StopLatched, entry.Acknowledgement = false, ack
	}
	if !enabled {
		entry.Condition = disabled
		return e.save(ctx, consumer.ID, &entry)
	}
	if acquisition != nil {
		return acquisition
	}
	material, err := publish.Material(output, c, consumer)
	if err != nil {
		return err
	}
	client, err := issue.Client(c.Endpoint, material)
	if err == nil {
		err = issue.ValidateConsumer(ctx, client, c, consumer)
	}
	if err != nil {
		// Do not silently reissue after revoked consumer authority.
		if err == provider.Auth || err == provider.Trust {
			entry.StopLatched, entry.Condition, entry.Acknowledgement = true, blocked, output.Annotations[Acknowledge]
			if saveErr := e.save(ctx, consumer.ID, &entry); saveErr != nil {
				return saveErr
			}
		}
		return err
	}
	if expires.After(e.Now().Add(time.Duration(c.Lifetime.RenewBeforeSeconds) * time.Second)) {
		entry.Condition = "CredentialPublished"
		return e.save(ctx, consumer.ID, &entry)
	}
	if e.Current == nil {
		return provider.Trust
	}
	if err := e.Current(ctx, generation); err != nil {
		return err
	}
	candidate, err := issue.Request(ctx, issuer, c, consumer, identity.CA, e.Now())
	if err != nil {
		return err
	}
	if err := e.Current(ctx, generation); err != nil {
		return err
	}
	if err := publish.Commit(ctx, e.Management, c, consumer, output, candidate, generation); err != nil {
		return err
	}
	entry.Expiry, entry.LastSuccess, entry.Condition = candidate.Expires, e.Now(), "CredentialPublished"
	return e.save(ctx, consumer.ID, &entry)
}
