package reconcile

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"regexp"
	"sync"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/issue"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/publish"
	"github.com/rayselfs/kube-token-requestor/internal/status"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

type Engine struct {
	Leader       func(context.Context) error
	Current      func(context.Context, string) error
	Management   kubernetes.Interface
	Store        *status.Store
	Providers    map[string]provider.IssuerProvider
	Now          func() time.Time
	Observe      func(cluster, consumer, result string, expiry time.Time)
	State        func(string, string, status.Consumer)
	Event        func(string, string, string, string)
	IssuerMetric func(string, time.Time, time.Time)
	mu           sync.Mutex
	blocked      map[string]string
	throttled    map[string]throttle
	retries      map[string]retry
	expiries     map[string]time.Time
}

var acknowledgement = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (e *Engine) Delay(c config.Cluster, requested time.Duration) time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, consumer := range c.Consumers {
		if expiry, ok := e.expiries[consumer.ID]; ok {
			remaining := expiry.Sub(e.Now()) - time.Duration(c.Lifetime.StopBeforeSeconds+c.Lifetime.ClockSkewSeconds)*time.Second
			requested = min(requested, max(time.Second, remaining))
		}
	}
	return requested
}

type throttle struct {
	revision string
	until    time.Time
}

type retry struct {
	failures int
	next     time.Time
}

func (e *Engine) inputs(ctx context.Context, c config.Cluster, generation string) (string, error) {
	revision := generation
	for _, ref := range []*config.Ref{c.Provider.Secret, c.Provider.TrustSecret, c.Provider.ClientSecret} {
		if ref == nil {
			continue
		}
		s, err := e.Management.CoreV1().Secrets(ref.Namespace).Get(ctx, ref.Name, meta.GetOptions{})
		if err != nil {
			return "", provider.Classify(err)
		}
		if string(s.UID) != ref.UID {
			return "", provider.Trust
		}
		revision += "/" + ref.UID + "/" + s.ResourceVersion
	}
	return revision, nil
}

func (e *Engine) save(ctx context.Context, id string, entry *status.Consumer) error {
	updated := *entry
	updated.Revision++
	err := e.Store.Update(ctx, func(s *status.Snapshot) error {
		if s.Consumers[id].Revision != entry.Revision {
			return provider.Conflict
		}
		s.Consumers[id] = updated
		return nil
	})
	if err == nil {
		*entry = updated
	}
	return err
}

// Slice isolates consumer failures. The queue ensures one slice per cluster at a time.
func (e *Engine) Slice(ctx context.Context, c config.Cluster, generation string, offset int, issuance bool) error {
	snapshot, err := e.Store.Read(ctx)
	if err != nil {
		return err
	}
	end := min(offset+4, len(c.Consumers))
	if issuance && e.Current != nil && e.Current(ctx, generation) != nil {
		issuance = false
	}
	// Enforce deadlines before potentially slow issuer/API acquisition.
	for _, consumer := range c.Consumers[offset:end] {
		output, readErr := publish.Read(ctx, e.Management, consumer)
		entry := snapshot.Consumers[consumer.ID]
		expires := entry.Expiry
		if readErr == nil {
			expires = publish.StoredExpiry(output, c, consumer)
		}
		if expires.After(e.Now().Add(time.Duration(c.Lifetime.StopBeforeSeconds+c.Lifetime.ClockSkewSeconds)*time.Second)) && !entry.StopLatched {
			continue
		}
		d, depErr := deployment(ctx, e.Management, consumer)
		if depErr != nil {
			return depErr
		}
		if *d.Spec.Replicas == 1 {
			entry.Expiry = expires
			if err := e.stop(ctx, consumer, &entry, "SafetyStopped"); err != nil {
				entry.Condition = "StopUnconfirmed"
				entry.StopLatched = true
				_ = e.save(ctx, consumer.ID, &entry)
				if e.State != nil {
					e.State(c.ID, consumer.ID, entry)
				}
				if e.Observe != nil {
					e.Observe(c.ID, consumer.ID, entry.Condition, expires)
				}
				return err
			}
			entry.StopLatched, entry.Intent = true, nil
			snapshot.Consumers[consumer.ID] = entry
		}
	}
	call, cancel := context.WithTimeout(ctx, e.Delay(c, 60*time.Second))
	defer cancel()
	ctx = call
	var issuer kubernetes.Interface
	var identity provider.IssuerCredential
	var acquisition error
	if issuance && *c.Enabled {
		revision, err := e.inputs(ctx, c, generation)
		acquisition = err
		authRevision := revision
		selected := e.Providers[c.Provider.Type]
		if acquisition == nil && selected != nil {
			marker, err := selected.InputRevision(ctx, c)
			if err != nil {
				acquisition = provider.Classify(err)
			} else if marker != "" {
				authRevision += "/" + marker
			}
		}
		e.mu.Lock()
		blocked := e.blocked[c.ID] == authRevision && authRevision != ""
		budget := e.throttled[c.ID]
		e.mu.Unlock()
		if blocked {
			acquisition = provider.Auth
		} else if acquisition == nil && budget.revision == revision && budget.until.After(e.Now()) {
			acquisition = &provider.Retry{After: budget.until.Sub(e.Now())}
		}
		attempted := false
		if acquisition != nil {
			// Retry only metadata after bootstrap rejection until a reviewed input changes.
		} else if selected == nil {
			acquisition = provider.Trust
		} else {
			attempted = true
			identity, acquisition = selected.Acquire(ctx, c)
			var limited *provider.Retry
			if errors.As(acquisition, &limited) {
				e.mu.Lock()
				if e.throttled == nil {
					e.throttled = map[string]throttle{}
				}
				e.throttled[c.ID] = throttle{revision: revision, until: e.Now().Add(min(limited.After, 5*time.Minute))}
				e.mu.Unlock()
			}
		}
		if attempted && c.Provider.Type == "OAuthTokenExchange" && e.Event != nil {
			outcome := "Healthy"
			if acquisition != nil {
				outcome = provider.Classify(acquisition).Error()
			}
			e.Event("exchange", c.ID, "", outcome)
		}
		if acquisition == nil && e.IssuerMetric != nil {
			e.IssuerMetric(c.ID, identity.Expires, identity.RotationDue)
		}
		if acquisition == nil {
			issuer, acquisition = issue.Client(c.Endpoint, identity)
		}
		if acquisition == nil {
			slice := c
			slice.Consumers = c.Consumers[offset:end]
			acquisition = issue.Issuer(ctx, issuer, slice)
		}
		if acquisition == provider.Auth {
			e.mu.Lock()
			if e.blocked == nil {
				e.blocked = map[string]string{}
			}
			e.blocked[c.ID] = authRevision
			e.mu.Unlock()
		}
	}
	last := acquisition
	for _, consumer := range c.Consumers[offset:end] {
		if ctx.Err() != nil {
			return provider.Transport
		}
		entry := snapshot.Consumers[consumer.ID]
		e.mu.Lock()
		deferred := e.retries[consumer.ID].next.After(e.Now())
		e.mu.Unlock()
		if deferred && !entry.StopLatched && entry.Expiry.After(e.Now().Add(time.Duration(c.Lifetime.StopBeforeSeconds+c.Lifetime.ClockSkewSeconds)*time.Second)) {
			continue
		}
		err := e.consumer(ctx, c, consumer, generation, entry, issuer, identity, acquisition, issuance && *c.Enabled && *consumer.Enabled)
		e.mu.Lock()
		if e.retries == nil {
			e.retries = map[string]retry{}
		}
		if err == nil {
			delete(e.retries, consumer.ID)
		} else if ctx.Err() == nil {
			state := e.retries[consumer.ID]
			state.failures = min(state.failures+1, 7)
			delay := wait.Jitter(min(5*time.Second*time.Duration(1<<(state.failures-1)), 250*time.Second), .2)
			var requested *provider.Retry
			if errors.As(err, &requested) {
				delay = max(delay, requested.After)
			}
			state.next = e.Now().Add(min(delay, 5*time.Minute))
			e.retries[consumer.ID] = state
		}
		e.mu.Unlock()
		if err != nil {
			last = provider.Classify(err)
		}
		if e.Observe != nil {
			result := "Healthy"
			if err != nil {
				result = provider.Classify(err).Error()
			}
			fresh, readErr := e.Store.Read(ctx)
			if readErr == nil {
				entry = fresh.Consumers[consumer.ID]
			}
			if err != nil && !entry.StopLatched && entry.Condition != "StopUnconfirmed" {
				entry.Condition = result
				_ = e.save(ctx, consumer.ID, &entry)
			}
			if entry.Condition != "" {
				result = entry.Condition
			}
			e.Observe(c.ID, consumer.ID, result, entry.Expiry)
			if e.State != nil {
				e.State(c.ID, consumer.ID, entry)
			}
		}
	}
	return last
}

func (e *Engine) consumer(ctx context.Context, c config.Cluster, consumer config.Consumer, generation string, entry status.Consumer,
	issuer kubernetes.Interface, identity provider.IssuerCredential, acquisition error, enabled bool) error {
	output, err := publish.Read(ctx, e.Management, consumer)
	if err != nil {
		return err
	}
	expires := publish.StoredExpiry(output, c, consumer)
	entry.Expiry = expires
	unsafe := !expires.After(e.Now().Add(time.Duration(c.Lifetime.StopBeforeSeconds+c.Lifetime.ClockSkewSeconds) * time.Second))
	d, err := deployment(ctx, e.Management, consumer)
	if err != nil {
		return err
	}
	e.mu.Lock()
	if e.expiries == nil {
		e.expiries = map[string]time.Time{}
	}
	if *d.Spec.Replicas == 1 {
		e.expiries[consumer.ID] = expires
	} else {
		delete(e.expiries, consumer.ID)
	}
	e.mu.Unlock()
	if *d.Spec.Replicas == 1 && !mounted(d, consumer) {
		return provider.Trust
	}
	// A persisted restart belongs to one policy/generation and deployment only.
	// Reconfiguration cancels it through a durable stop, never through an implicit resume.
	if entry.Intent != nil && (consumer.ReloadPolicy != "StopStart" || entry.Intent.Generation != generation || entry.Intent.DeploymentUID != consumer.CADeployment.UID) {
		entry.Acknowledgement = d.Annotations[Acknowledge]
		return e.stop(ctx, consumer, &entry, "SafetyStopped")
	}
	if entry.StopLatched {
		ack := d.Annotations[Acknowledge]
		if ack != "" && !acknowledgement.MatchString(ack) {
			return provider.Trust
		}
		// A fresh operator nonce acknowledges only this consumer after replacement is healthy.
		if enabled && !unsafe && ack != "" && ack != entry.Acknowledgement {
			client, err := issue.Client(c.Endpoint, provider.IssuerCredential{Bearer: string(output.Data["token"]), CA: output.Data["ca.crt"]})
			if err != nil {
				return err
			}
			if err := issue.ValidateConsumer(ctx, client, c, consumer); err != nil {
				return err
			}
			entry.StopLatched, entry.Acknowledgement, entry.Condition = false, ack, "Healthy"
			if err := e.save(ctx, consumer.ID, &entry); err != nil {
				return err
			}
		} else if *d.Spec.Replicas == 1 {
			return e.stop(ctx, consumer, &entry, "SafetyStopped")
		}
	}
	if !enabled {
		if unsafe && *d.Spec.Replicas == 1 {
			return e.stop(ctx, consumer, &entry, "SafetyStopped")
		}
		return nil
	}
	if acquisition != nil {
		entry.Condition = provider.Classify(acquisition).Error()
		if unsafe && *d.Spec.Replicas == 1 {
			if err := e.stop(ctx, consumer, &entry, "SafetyStopped"); err != nil {
				entry.Condition = "StopUnconfirmed"
				_ = e.save(ctx, consumer.ID, &entry)
				return err
			}
		} else {
			_ = e.save(ctx, consumer.ID, &entry)
		}
		return acquisition
	}
	if !unsafe && entry.Intent == nil && expires.After(e.Now().Add(time.Duration(c.Lifetime.RenewBeforeSeconds)*time.Second)) {
		client, err := issue.Client(c.Endpoint, provider.IssuerCredential{Bearer: string(output.Data["token"]), CA: output.Data["ca.crt"]})
		if err != nil {
			return err
		}
		if err := issue.ValidateConsumer(ctx, client, c, consumer); err == nil {
			return e.save(ctx, consumer.ID, &entry)
		} else if err != provider.Auth {
			return err
		}
		// A valid issuer can rescue a revoked consumer without trusting its decoded expiry.
	}
	// Recover publication-before-status crashes by checking the durable output's generation/expiry.
	if entry.Intent != nil && entry.Intent.Generation == generation && output.Annotations[publish.Generation] == generation && expires.Equal(entry.Intent.CandidateExpiry) {
		client, err := issue.Client(c.Endpoint, provider.IssuerCredential{Bearer: string(output.Data["token"]), CA: output.Data["ca.crt"]})
		if err != nil {
			return err
		}
		if err := issue.ValidateConsumer(ctx, client, c, consumer); err != nil {
			return err
		}
		entry.Intent.Phase = "Published"
		if err := e.save(ctx, consumer.ID, &entry); err != nil {
			return err
		}
		return e.resume(ctx, consumer, &entry, generation)
	}
	if e.Current != nil {
		if err := e.Current(ctx, generation); err != nil {
			return err
		}
	}
	candidate, err := issue.Request(ctx, issuer, c, consumer, identity.CA, e.Now())
	if e.Event != nil {
		outcome := "Healthy"
		if err != nil {
			outcome = provider.Classify(err).Error()
		}
		e.Event("token", c.ID, consumer.ID, outcome)
	}
	if err != nil {
		if unsafe && *d.Spec.Replicas == 1 {
			_ = e.stop(ctx, consumer, &entry, "SafetyStopped")
		}
		return err
	}
	if consumer.ReloadPolicy == "StopStart" && !entry.StopLatched && (*d.Spec.Replicas == 1 || entry.Intent != nil) {
		if entry.Intent == nil {
			id := make([]byte, 16)
			if _, err := rand.Read(id); err != nil {
				return provider.Transport
			}
			entry.Intent = &status.Intent{Operation: hex.EncodeToString(id), Generation: generation, DeploymentUID: consumer.CADeployment.UID, Replicas: 1, CandidateExpiry: candidate.Expires, Phase: "Stopping"}
		} else if entry.Intent.Generation != generation || entry.Intent.DeploymentUID != consumer.CADeployment.UID {
			return provider.Trust
		} else {
			entry.Intent.CandidateExpiry = candidate.Expires
		}
		if err := e.save(ctx, consumer.ID, &entry); err != nil {
			return err
		}
		if err := e.stopRenewal(ctx, consumer, &entry, *d.Spec.Replicas); err != nil {
			return err
		}
	}
	if ctx.Err() != nil {
		return provider.Transport
	}
	if e.Current != nil {
		if err := e.Current(ctx, generation); err != nil {
			return err
		}
	}
	if err := publish.Commit(ctx, e.Management, c, consumer, output, candidate, generation); err != nil {
		if err == provider.Conflict && e.Event != nil {
			e.Event("conflict", c.ID, consumer.ID, "Conflict")
		}
		return err
	}
	entry.Expiry, entry.LastSuccess, entry.Condition = candidate.Expires, e.Now(), "Healthy"
	if entry.StopLatched {
		entry.Condition = "SafetyStopped"
	}
	if entry.Intent != nil {
		entry.Intent.Phase = "Published"
	}
	if err := e.save(ctx, consumer.ID, &entry); err != nil {
		return err
	}
	if entry.Intent != nil && !entry.StopLatched {
		return e.resume(ctx, consumer, &entry, generation)
	}
	return nil
}
