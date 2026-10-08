package issue

import (
	"context"
	"testing"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/testutil"
	auth "k8s.io/api/authentication/v1"
	authz "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
	for _, mode := range []string{"valid", "wrong-uid", "wrong-principal", "privileged", "wildcard-token"} {
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
			client := fake.NewClientset()
			client.PrependReactor("create", "serviceaccounts", func(a kt.Action) (bool, runtime.Object, error) {
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
		})
	}
}
