package reconcile

import (
	"context"
	"testing"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/status"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

type throttledProvider struct{ calls int }

func (p *throttledProvider) Acquire(context.Context, config.Cluster) (provider.IssuerCredential, error) {
	p.calls++
	return provider.IssuerCredential{}, &provider.Retry{After: 2 * time.Minute}
}
func TestSafetyWakeDoesNotBypassIssuerRetryAfter(t *testing.T) {
	now := time.Unix(2000000000, 0)
	client := fake.NewClientset(&core.ConfigMap{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "status", UID: "uid"}})
	p := &throttledProvider{}
	e := &Engine{Management: client, Store: &status.Store{Client: client, Namespace: "ns", Name: "status", UID: "uid"}, Now: func() time.Time { return now }, Providers: map[string]provider.IssuerProvider{"OAuthTokenExchange": p}}
	enabled := true
	c := config.Cluster{ID: "child", Enabled: &enabled, Provider: config.Provider{Type: "OAuthTokenExchange"}}
	_ = e.Slice(context.Background(), c, "generation", 0, true)
	now = now.Add(5 * time.Second)
	_ = e.Slice(context.Background(), c, "generation", 0, true)
	if p.calls != 1 {
		t.Fatal("safety wake bypassed provider throttle")
	}
	now = now.Add(2 * time.Minute)
	_ = e.Slice(context.Background(), c, "generation", 0, true)
	if p.calls != 2 {
		t.Fatal("provider did not recover after Retry-After")
	}
	_ = e.Slice(context.Background(), c, "reviewed-new-generation", 0, true)
	if p.calls != 3 {
		t.Fatal("reviewed input change did not reset old provider budget")
	}
}
