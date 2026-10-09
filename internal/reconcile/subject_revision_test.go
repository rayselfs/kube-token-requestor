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

type changingSubject struct {
	revision string
	calls    int
}

func (p *changingSubject) InputRevision(context.Context, config.Cluster) (string, error) {
	return p.revision, nil
}
func (p *changingSubject) Acquire(context.Context, config.Cluster) (provider.IssuerCredential, error) {
	p.calls++
	return provider.IssuerCredential{}, provider.Auth
}
func TestProjectedSubjectChangeRecoversCachedAuthenticationRejection(t *testing.T) {
	client := fake.NewClientset(&core.ConfigMap{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "status", UID: "uid"}})
	p := &changingSubject{revision: "old-subject-fingerprint"}
	e := &Engine{Management: client, Store: &status.Store{Client: client, Namespace: "ns", Name: "status", UID: "uid"}, Now: time.Now, Providers: map[string]provider.IssuerProvider{"OAuthTokenExchange": p}}
	enabled := true
	c := config.Cluster{ID: "child", Enabled: &enabled, Provider: config.Provider{Type: "OAuthTokenExchange"}}
	_ = e.Slice(context.Background(), c, "unchanged-registry", 0, true)
	_ = e.Slice(context.Background(), c, "unchanged-registry", 0, true)
	if p.calls != 1 {
		t.Fatal("unchanged rejected subject caused repeated exchange")
	}
	p.revision = "new-subject-fingerprint"
	_ = e.Slice(context.Background(), c, "unchanged-registry", 0, true)
	if p.calls != 2 {
		t.Fatal("projected subject rotation did not recover authentication without unrelated Secret mutation")
	}
	_ = e.Slice(context.Background(), c, "unchanged-registry", 0, true)
	if p.calls != 2 {
		t.Fatal("new rejected subject caused a hot loop")
	}
}
