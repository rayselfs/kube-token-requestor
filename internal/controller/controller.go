package controller

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/observe"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/reconcile"
	"github.com/rayselfs/kube-token-requestor/internal/status"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/util/workqueue"
)

type Options struct{ Namespace, Registry, Status, Lease, Identity, SubjectRoot string }
type runtime struct {
	client      kubernetes.Interface
	opts        Options
	metrics     *observe.Metrics
	engine      *reconcile.Engine
	mu          sync.RWMutex
	registry    *config.Registry
	generation  string
	registryUID string
	valid       bool
	ctx         context.Context
	cancel      context.CancelFunc
	offsets     map[string]int
	offsetMu    sync.Mutex
}

func Run(ctx context.Context, opts Options, metrics *observe.Metrics) error {
	for _, value := range []string{opts.Namespace, opts.Registry, opts.Status, opts.Lease, opts.Identity} {
		if value == "" {
			return provider.Trust
		}
	}
	inCluster, err := rest.InClusterConfig()
	if err != nil {
		return provider.Auth
	}
	inCluster.Timeout, inCluster.QPS, inCluster.Burst = 10*time.Second, 10, 20
	inCluster.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	inCluster.WarningHandler = rest.NoWarnings{}
	httpClient, err := rest.HTTPClientFor(inCluster)
	if err != nil {
		return provider.Trust
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return provider.Trust }
	client, err := kubernetes.NewForConfigAndClient(inCluster, httpClient)
	if err != nil {
		return provider.Trust
	}
	startup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	version, err := client.Discovery().ServerVersion()
	if err != nil {
		return provider.Classify(err)
	}
	if version.Major != "1" || (version.Minor != "34" && version.Minor != "35" && version.Minor != "36") {
		return provider.Trust
	}
	state, err := client.CoreV1().ConfigMaps(opts.Namespace).Get(startup, opts.Status, meta.GetOptions{})
	if err != nil {
		return provider.Classify(err)
	}
	lease, err := client.CoordinationV1().Leases(opts.Namespace).Get(startup, opts.Lease, meta.GetOptions{})
	if err != nil {
		return provider.Classify(err)
	}
	store := &status.Store{Client: client, Namespace: opts.Namespace, Name: opts.Status, UID: string(state.UID)}
	if _, err := store.Read(startup); err != nil {
		return err
	}
	r := &runtime{client: client, opts: opts, metrics: metrics, offsets: map[string]int{}}
	r.engine = &reconcile.Engine{Management: client, Store: store, Now: time.Now, Observe: metrics.Record, State: metrics.State, Event: metrics.Event, IssuerMetric: metrics.Issuer, Providers: map[string]provider.IssuerProvider{
		"SecretIssuer": provider.SecretIssuer{Management: client, Now: time.Now},
		"OAuthTokenExchange": provider.OAuthTokenExchange{Management: client, Now: time.Now, Subject: func(volume string) ([]byte, error) {
			if volume == "" || strings.ContainsAny(volume, "/\\.") || opts.SubjectRoot == "" {
				return nil, provider.Trust
			}
			f, err := os.Open(filepath.Join(opts.SubjectRoot, volume, "token"))
			if err != nil {
				return nil, provider.Auth
			}
			defer f.Close()
			data, err := io.ReadAll(io.LimitReader(f, 32769))
			if err != nil || len(data) > 32768 {
				return nil, provider.Auth
			}
			return data, nil
		}},
	}}
	if err := r.reload(startup, ctx); err != nil {
		return err
	}
	ctx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	done := make(chan struct{})
	lock := &Lock{Client: client, Namespace: opts.Namespace, Name: opts.Lease, UID: string(lease.UID), Holder: opts.Identity}
	elector, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock:          lock,
		LeaseDuration: 30 * time.Second, RenewDeadline: 20 * time.Second, RetryPeriod: 5 * time.Second,
		ReleaseOnCancel: false, Name: "kube-token-requestor",
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(leader context.Context) {
				metrics.Leader.Store(true)
				metrics.Changes.Add(1)
				defer close(done)
				r.lead(leader)
			},
			OnStoppedLeading: func() { metrics.Ready.Store(false); cancelRun() },
		},
	})
	if err != nil {
		return provider.Trust
	}
	metrics.Ready.Store(true)
	pollDone := make(chan struct{})
	go func() {
		defer close(pollDone)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				call, cancel := context.WithTimeout(ctx, 20*time.Second)
				_ = r.reload(call, ctx)
				_, _, leaseErr := lock.Get(call)
				metrics.Ready.Store(metrics.Valid.Load() && leaseErr == nil)
				metrics.Progress.Store(time.Now().Unix())
				cancel()
			}
		}
	}()
	elector.Run(ctx)
	cancelRun()
	<-pollDone
	if metrics.Leader.Load() {
		<-done
	}
	metrics.Leader.Store(false)
	// Lease expires naturally after workers drain; it is never released ahead of in-flight work.
	return nil
}

func (r *runtime) reload(call, parent context.Context) error {
	object, err := r.client.CoreV1().ConfigMaps(r.opts.Namespace).Get(call, r.opts.Registry, meta.GetOptions{})
	var parsed *config.Registry
	if err == nil {
		if r.registryUID != "" && r.registryUID != string(object.UID) {
			err = provider.Trust
		} else {
			parsed, err = config.Parse(strings.NewReader(object.Data["registry.json"]))
		}
	}
	if err == nil {
		identity, getErr := r.client.CoreV1().Namespaces().Get(call, "kube-system", meta.GetOptions{})
		if getErr != nil {
			err = provider.Classify(getErr)
		} else if string(identity.UID) != parsed.ManagementUID {
			err = provider.Trust
		}
	}
	data, _ := json.Marshal(parsed)
	generation := credential.Hash(data)
	r.mu.RLock()
	unchanged := err == nil && r.valid && r.generation == generation
	cancel := r.cancel
	r.mu.RUnlock()
	if unchanged {
		r.metrics.Ready.Store(true)
		return nil
	}
	if cancel != nil {
		cancel()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err == nil {
		err = r.transition(call, parsed)
	}
	if err == nil {
		err = r.engine.Store.Update(call, func(s *status.Snapshot) error { s.Generation = generation; return nil })
	}
	r.valid = err == nil
	r.metrics.Valid.Store(r.valid)
	r.metrics.Ready.Store(r.valid)
	if err == nil {
		r.registry, r.generation, r.registryUID = parsed, generation, string(object.UID)
		r.metrics.Reset()
		count := int64(0)
		for _, c := range parsed.Clusters {
			for _, v := range c.Consumers {
				if *c.Enabled && *v.Enabled {
					count++
				}
			}
		}
		r.metrics.Targets.Store(count)
	} else if r.registry == nil {
		return provider.Trust
	}
	r.ctx, r.cancel = context.WithCancel(parent)
	return nil
}

func (r *runtime) lead(ctx context.Context) {
	limiter := workqueue.NewTypedItemExponentialFailureRateLimiter[string](5*time.Second, 5*time.Minute)
	queue := workqueue.NewTypedRateLimitingQueue(limiter)
	defer queue.ShutDown()
	var workers sync.WaitGroup
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				key, shutdown := queue.Get()
				if shutdown {
					return
				}
				r.mu.RLock()
				var target *config.Cluster
				for i := range r.registry.Clusters {
					if r.registry.Clusters[i].ID == key {
						target = &r.registry.Clusters[i]
						break
					}
				}
				if target != nil {
					call, cancel := context.WithTimeout(r.ctx, 60*time.Second)
					// Leadership cancellation is independent of registry generations.
					stop := context.AfterFunc(ctx, cancel)
					r.offsetMu.Lock()
					offset := r.offsets[key]
					if offset >= len(target.Consumers) {
						offset = 0
					}
					r.offsetMu.Unlock()
					identity, err := r.client.CoreV1().Namespaces().Get(call, "kube-system", meta.GetOptions{})
					if err == nil && string(identity.UID) != r.registry.ManagementUID {
						err = provider.Trust
					}
					if err == nil {
						start := time.Now()
						err = r.engine.Slice(call, *target, r.generation, offset, r.valid)
						r.metrics.Duration(target.ID, time.Since(start))
					}
					cancel()
					stop()
					r.offsetMu.Lock()
					r.offsets[key] = offset + 4
					if r.offsets[key] >= len(target.Consumers) {
						r.offsets[key] = 0
					}
					r.offsetMu.Unlock()
					if err != nil {
						queue.AddAfter(key, r.engine.Delay(*target, limiter.When(key)))
					} else {
						queue.Forget(key)
						queue.AddAfter(key, r.engine.Delay(*target, 30*time.Second))
					}
				}
				r.mu.RUnlock()
				queue.Done(key)
				r.metrics.Depth.Store(int64(queue.Len()))
			}
		}()
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		r.mu.RLock()
		for _, target := range r.registry.Clusters {
			queue.Add(target.ID)
		}
		r.mu.RUnlock()
		select {
		case <-ctx.Done():
			r.mu.RLock()
			r.cancel()
			r.mu.RUnlock()
			queue.ShutDown()
			workers.Wait()
			return
		case <-ticker.C:
		}
	}
}
