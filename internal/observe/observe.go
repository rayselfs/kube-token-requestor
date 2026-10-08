package observe

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	"github.com/rayselfs/kube-token-requestor/internal/status"
)

type Metrics struct {
	Progress                                                     atomic.Int64
	Leader, Valid, Ready                                         atomic.Bool
	Changes                                                      atomic.Uint64
	Depth, Targets                                               atomic.Int64
	once                                                         sync.Once
	base, targets                                                *prometheus.Registry
	reconcile, requests, exchange, conflicts                     *prometheus.CounterVec
	duration                                                     *prometheus.HistogramVec
	expiry, success, observed, condition, issuerExpiry, rotation *prometheus.GaugeVec
}

func (m *Metrics) init() {
	m.once.Do(func() {
		m.Progress.Store(time.Now().Unix())
		m.base = prometheus.NewRegistry()
		m.targets = prometheus.NewRegistry()
		for _, g := range []struct {
			name string
			get  func() float64
		}{
			{"leader", func() float64 { return boolean(m.Leader.Load()) }},
			{"config_valid", func() float64 { return boolean(m.Valid.Load()) }},
			{"queue_depth", func() float64 { return float64(m.Depth.Load()) }},
			{"registry_targets", func() float64 { return float64(m.Targets.Load()) }},
		} {
			m.base.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Namespace: "kube_token_requestor", Name: g.name, Help: g.name}, g.get))
		}
		m.base.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{Namespace: "kube_token_requestor", Name: "leadership_changes_total", Help: "Leadership transitions observed by this process"}, func() float64 { return float64(m.Changes.Load()) }))
		m.base.MustRegister(prometheus.NewGoCollector(), prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
		counter := func(name string, labels []string) *prometheus.CounterVec {
			v := prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "kube_token_requestor", Name: name, Help: name}, labels)
			m.targets.MustRegister(v)
			return v
		}
		gauge := func(name string, labels []string) *prometheus.GaugeVec {
			v := prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: "kube_token_requestor", Name: name, Help: name}, labels)
			m.targets.MustRegister(v)
			return v
		}
		m.reconcile = counter("reconcile_total", []string{"cluster", "consumer", "result"})
		m.requests = counter("token_request_total", []string{"cluster", "consumer", "result"})
		m.exchange = counter("exchange_total", []string{"cluster", "result"})
		m.conflicts = counter("secret_conflicts_total", []string{"cluster", "consumer"})
		m.duration = prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: "kube_token_requestor", Name: "reconcile_duration_seconds", Help: "Reconcile slice duration", Buckets: []float64{.1, .5, 1, 5, 10, 30, 60}}, []string{"cluster"})
		m.targets.MustRegister(m.duration)
		m.expiry = gauge("token_expiry_timestamp_seconds", []string{"cluster", "consumer"})
		m.success = gauge("last_success_timestamp_seconds", []string{"cluster", "consumer"})
		m.observed = gauge("last_observed_timestamp_seconds", []string{"cluster", "consumer"})
		m.condition = gauge("condition", []string{"cluster", "consumer", "condition"})
		m.issuerExpiry = gauge("issuer_expiry_timestamp_seconds", []string{"cluster"})
		m.rotation = gauge("issuer_rotation_due_timestamp_seconds", []string{"cluster"})
	})
}
func boolean(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

var conditions = []string{"Healthy", "Transport", "TrustRejected", "BootstrapRequired", "Conflict", "SafetyStopped", "StopUnconfirmed"}

func result(value string) string {
	for _, v := range conditions {
		if v == value {
			return v
		}
	}
	return "TrustRejected"
}
func (m *Metrics) Record(cluster, consumer, outcome string, expiry time.Time) {
	m.init()
	m.reconcile.WithLabelValues(cluster, consumer, result(outcome)).Inc()
	m.observed.WithLabelValues(cluster, consumer).Set(float64(time.Now().Unix()))
	if !expiry.IsZero() {
		m.expiry.WithLabelValues(cluster, consumer).Set(float64(expiry.Unix()))
	}
}
func (m *Metrics) State(cluster, consumer string, s status.Consumer) {
	m.init()
	for _, v := range conditions {
		m.condition.WithLabelValues(cluster, consumer, v).Set(boolean(v == s.Condition))
	}
	if !s.LastSuccess.IsZero() {
		m.success.WithLabelValues(cluster, consumer).Set(float64(s.LastSuccess.Unix()))
	}
}
func (m *Metrics) Duration(cluster string, elapsed time.Duration) {
	m.init()
	m.duration.WithLabelValues(cluster).Observe(elapsed.Seconds())
}
func (m *Metrics) Event(kind, cluster, consumer, outcome string) {
	m.init()
	switch kind {
	case "token":
		m.requests.WithLabelValues(cluster, consumer, result(outcome)).Inc()
	case "exchange":
		m.exchange.WithLabelValues(cluster, result(outcome)).Inc()
	case "conflict":
		m.conflicts.WithLabelValues(cluster, consumer).Inc()
	}
}
func (m *Metrics) Issuer(cluster string, expiry, rotation time.Time) {
	m.init()
	if expiry.IsZero() {
		m.issuerExpiry.DeleteLabelValues(cluster)
	} else {
		m.issuerExpiry.WithLabelValues(cluster).Set(float64(expiry.Unix()))
	}
	if rotation.IsZero() {
		m.rotation.DeleteLabelValues(cluster)
	} else {
		m.rotation.WithLabelValues(cluster).Set(float64(rotation.Unix()))
	}
}

// Reset removes offboarded label series. A newly accepted generation starts a fresh bounded metric set.
func (m *Metrics) Reset() {
	m.init()
	m.reconcile.Reset()
	m.requests.Reset()
	m.exchange.Reset()
	m.conflicts.Reset()
	m.duration.Reset()
	m.expiry.Reset()
	m.success.Reset()
	m.observed.Reset()
	m.condition.Reset()
	m.issuerExpiry.Reset()
	m.rotation.Reset()
}
func (m *Metrics) Gather() ([]*dto.MetricFamily, error) {
	m.init()
	base, err := m.base.Gather()
	if err != nil || !m.Leader.Load() {
		return base, err
	}
	targets, err := m.targets.Gather()
	return append(base, targets...), err
}
func (m *Metrics) Handler() http.Handler {
	m.init()
	mux := http.NewServeMux()
	mux.HandleFunc("/livez", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		if time.Now().Unix()-m.Progress.Load() > 120 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if !m.Ready.Load() {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	})
	mux.Handle("/metrics", promhttp.HandlerFor(m, promhttp.HandlerOpts{ErrorHandling: promhttp.HTTPErrorOnError}))
	return mux
}
