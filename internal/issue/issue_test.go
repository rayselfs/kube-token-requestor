package issue

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/testutil"
	auth "k8s.io/api/authentication/v1"
	authz "k8s.io/api/authorization/v1"
	coord "k8s.io/api/coordination/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/version"
	fd "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes/fake"
	kt "k8s.io/client-go/testing"
)

func TestClientRejectsPlaintextAPI(t *testing.T) {
	if _, err := Client("http://api.example.invalid:6443", provider.IssuerCredential{Bearer: "synthetic-canary"}); err != provider.Trust {
		t.Fatal("plaintext endpoint accepted")
	}
}

func TestIssuerIdentityAndNamedPermissions(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-uid", "wrong-principal", "privileged", "wildcard-token", "secret-list"} {
		t.Run(mode, func(t *testing.T) {
			c := config.Cluster{KubeSystemUID: "cluster-uid", IdentityNamespace: "identity", ExpectedIssuer: config.Principal{Username: "issuer", Groups: []string{"system:authenticated"}}, Consumers: []config.Consumer{{ServiceAccount: config.ServiceAccount{Name: "ca", UID: "ca-uid"}}}}
			client := fake.NewClientset(&core.Namespace{ObjectMeta: meta.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}}, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Namespace: "identity", Name: "ca", UID: "ca-uid"}})
			client.Discovery().(*fd.FakeDiscovery).FakedServerVersion = &version.Info{Major: "1", Minor: "35"}
			client.PrependReactor("create", "selfsubjectreviews", func(kt.Action) (bool, runtime.Object, error) {
				username, groups := "issuer", []string{"system:authenticated"}
				if mode == "wrong-principal" {
					username = "someone-else"
				}
				if mode == "privileged" {
					groups = append(groups, "system:masters")
				}
				return true, &auth.SelfSubjectReview{Status: auth.SelfSubjectReviewStatus{UserInfo: auth.UserInfo{Username: username, Groups: groups}}}, nil
			})
			client.PrependReactor("create", "selfsubjectaccessreviews", func(a kt.Action) (bool, runtime.Object, error) {
				attr := a.(kt.CreateAction).GetObject().(*authz.SelfSubjectAccessReview).Spec.ResourceAttributes
				allowed := attr.Resource == "serviceaccounts" && attr.Subresource == "token" && (attr.Name == "ca" || mode == "wildcard-token")
				return true, &authz.SelfSubjectAccessReview{Status: authz.SubjectAccessReviewStatus{Allowed: allowed}}, nil
			})
			client.PrependReactor("create", "selfsubjectrulesreviews", func(kt.Action) (bool, runtime.Object, error) {
				rules := []authz.ResourceRule{}
				if mode == "secret-list" {
					rules = append(rules, authz.ResourceRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"list"}})
				}
				return true, &authz.SelfSubjectRulesReview{Status: authz.SubjectRulesReviewStatus{ResourceRules: rules}}, nil
			})
			if mode == "wrong-uid" {
				c.KubeSystemUID = "wrong"
			}
			err := Issuer(context.Background(), client, c)
			if (err == nil) != (mode == "valid") {
				t.Fatal("identity or named permission guard incorrect")
			}
		})
	}
}

func TestInvalidTokenRequestResponseNeverPublishes(t *testing.T) {
	now := time.Unix(2000000000, 0)
	for _, mode := range []string{"expired", "wrong-sa", "wrong-audience", "wrong-expiry", "short-ttl"} {
		t.Run(mode, func(t *testing.T) {
			c := config.Cluster{IdentityNamespace: "identity", Audiences: []string{"api"}, Lifetime: config.Lifetime{RequestedSeconds: 600, AcceptedMinSeconds: 590, AcceptedMaxSeconds: 610, ClockSkewSeconds: 5}}
			consumer := config.Consumer{ServiceAccount: config.ServiceAccount{Name: "ca", UID: "ca-uid"}}
			client := fake.NewClientset(&core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Namespace: "identity", Name: "ca", UID: "ca-uid"}})
			client.PrependReactor("create", "selfsubjectaccessreviews", func(kt.Action) (bool, runtime.Object, error) {
				return true, &authz.SelfSubjectAccessReview{Status: authz.SubjectAccessReviewStatus{Allowed: true}}, nil
			})
			requested := false
			client.PrependReactor("create", "serviceaccounts", func(a kt.Action) (bool, runtime.Object, error) {
				requested = true
				if a.GetSubresource() != "token" {
					t.Fatal("unexpected create")
				}
				issued := now
				ttl := int64(600)
				uid := "ca-uid"
				aud := []string{"api"}
				expiry := now.Add(600 * time.Second)
				switch mode {
				case "expired":
					issued = now.Add(-time.Hour)
				case "wrong-sa":
					uid = "wrong"
				case "wrong-audience":
					aud = []string{"other"}
				case "wrong-expiry":
					expiry = expiry.Add(time.Second)
				case "short-ttl":
					ttl = 60
				}
				return true, &auth.TokenRequest{Status: auth.TokenRequestStatus{Token: testutil.Token("system:serviceaccount:identity:ca", "identity", "ca", uid, aud, issued, ttl), ExpirationTimestamp: meta.NewTime(expiry)}}, nil
			})
			if _, err := Request(context.Background(), client, c, consumer, nil, now); err != provider.Auth {
				t.Fatal("invalid response crossed credential boundary")
			}
			if !requested {
				t.Fatal("invalid-response test did not reach TokenRequest")
			}
		})
	}
}

func TestConsumerLeaseUIDAndCrossNamespaceAuthority(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-uid", "cross-namespace-update", "other-name-update", "missing"} {
		t.Run(mode, func(t *testing.T) {
			consumer := config.Consumer{ServiceAccount: config.ServiceAccount{Name: "ca", UID: "ca-uid"}, PermissionProfile: "ca-read-events-lease", LeaderElectionLease: &config.Ref{Namespace: "identity", Name: "ca-leader", UID: "lease-uid"}}
			c := config.Cluster{IdentityNamespace: "identity", KubeSystemUID: "cluster-uid", Consumers: []config.Consumer{consumer}}
			client := fake.NewClientset(&core.Namespace{ObjectMeta: meta.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}}, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Namespace: "identity", Name: "ca", UID: "ca-uid"}})
			client.Discovery().(*fd.FakeDiscovery).FakedServerVersion = &version.Info{Major: "1", Minor: "35"}
			client.PrependReactor("create", "selfsubjectreviews", func(kt.Action) (bool, runtime.Object, error) {
				return true, &auth.SelfSubjectReview{Status: auth.SelfSubjectReviewStatus{UserInfo: auth.UserInfo{Username: "system:serviceaccount:identity:ca", Groups: []string{"system:serviceaccounts", "system:serviceaccounts:identity", "system:authenticated"}}}}, nil
			})
			client.PrependReactor("create", "selfsubjectrulesreviews", func(kt.Action) (bool, runtime.Object, error) {
				return true, &authz.SelfSubjectRulesReview{Status: authz.SubjectRulesReviewStatus{ResourceRules: []authz.ResourceRule{{APIGroups: []string{"coordination.k8s.io"}, Resources: []string{"leases"}, Verbs: []string{"get", "update"}, ResourceNames: []string{"ca-leader"}}}}}, nil
			})
			client.PrependReactor("get", "leases", func(kt.Action) (bool, runtime.Object, error) {
				if mode == "missing" {
					return true, nil, provider.Auth
				}
				uid := "lease-uid"
				if mode == "wrong-uid" {
					uid = "other"
				}
				return true, &coord.Lease{ObjectMeta: meta.ObjectMeta{Namespace: "identity", Name: "ca-leader", UID: types.UID(uid)}}, nil
			})
			client.PrependReactor("create", "selfsubjectaccessreviews", func(a kt.Action) (bool, runtime.Object, error) {
				attr := a.(kt.CreateAction).GetObject().(*authz.SelfSubjectAccessReview).Spec.ResourceAttributes
				allowed := attr.Verb == "list" && attr.Resource != "secrets" || attr.Resource == "events" && attr.Verb == "create"
				if attr.Resource == "leases" {
					allowed = attr.Namespace == "identity" && attr.Name == "ca-leader" && (attr.Verb == "get" || attr.Verb == "update")
					if mode == "cross-namespace-update" && attr.Verb == "update" {
						allowed = true
					}
					if mode == "other-name-update" && attr.Verb == "update" && attr.Namespace == "identity" {
						allowed = true
					}
				}
				return true, &authz.SelfSubjectAccessReview{Status: authz.SubjectAccessReviewStatus{Allowed: allowed}}, nil
			})
			err := ValidateConsumer(context.Background(), client, c, consumer)
			if (err == nil) != (mode == "valid") {
				t.Fatal("Lease UID/scope guard incorrect")
			}
			for _, a := range client.Actions() {
				if a.GetResource().Resource == "leases" && a.GetVerb() != "get" {
					t.Fatal("consumer validation mutated Lease")
				}
			}
		})
	}
}

func TestIssuerAuditsFullEnrollmentWithBoundedConsumerChecks(t *testing.T) {
	c := config.Cluster{KubeSystemUID: "cluster-uid", IdentityNamespace: "identity", ExpectedIssuer: config.Principal{Username: "issuer", Groups: []string{"system:authenticated"}}}
	objects := []runtime.Object{&core.Namespace{ObjectMeta: meta.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}}}
	names := []string{}
	for i := range 100 {
		name := fmt.Sprintf("ca-%d", i)
		uid := fmt.Sprintf("uid-%d", i)
		c.Consumers = append(c.Consumers, config.Consumer{ServiceAccount: config.ServiceAccount{Name: name, UID: uid}})
		names = append(names, name)
		objects = append(objects, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "identity", UID: types.UID(uid)}})
	}
	client := fake.NewClientset(objects...)
	client.Discovery().(*fd.FakeDiscovery).FakedServerVersion = &version.Info{Major: "1", Minor: "35"}
	client.PrependReactor("create", "selfsubjectreviews", func(kt.Action) (bool, runtime.Object, error) {
		return true, &auth.SelfSubjectReview{Status: auth.SelfSubjectReviewStatus{UserInfo: auth.UserInfo{Username: "issuer", Groups: c.ExpectedIssuer.Groups}}}, nil
	})
	client.PrependReactor("create", "selfsubjectrulesreviews", func(kt.Action) (bool, runtime.Object, error) {
		return true, &authz.SelfSubjectRulesReview{Status: authz.SubjectRulesReviewStatus{ResourceRules: []authz.ResourceRule{{APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, Verbs: []string{"create"}, ResourceNames: names}}}}, nil
	})
	checks := 0
	client.PrependReactor("create", "selfsubjectaccessreviews", func(a kt.Action) (bool, runtime.Object, error) {
		attr := a.(kt.CreateAction).GetObject().(*authz.SelfSubjectAccessReview).Spec.ResourceAttributes
		allowed := attr.Resource == "serviceaccounts" && attr.Subresource == "token" && attr.Name != "unregistered-requestor-denial-probe"
		if allowed {
			checks++
		}
		return true, &authz.SelfSubjectAccessReview{Status: authz.SubjectAccessReviewStatus{Allowed: allowed}}, nil
	})
	if err := IssuerForConsumers(context.Background(), client, c, c.Consumers[12:16]); err != nil {
		t.Fatal("sliced review rejected legitimate enrolled grants", err)
	}
	if checks != 4 {
		t.Fatal("positive checks exceeded bounded queue slice")
	}
	for _, a := range client.Actions() {
		if a.GetVerb() == "get" && a.GetResource().Resource == "serviceaccounts" {
			n := a.(kt.GetAction).GetName()
			if n != "ca-12" && n != "ca-13" && n != "ca-14" && n != "ca-15" {
				t.Fatal("looked up unrelated consumer")
			}
		}
	}
	names = append(names, "foreign")
	if err := IssuerForConsumers(context.Background(), client, c, c.Consumers[12:16]); err != provider.Auth {
		t.Fatal("full enrollment audit accepted foreign grant", err)
	}
}
