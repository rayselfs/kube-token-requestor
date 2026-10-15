package issue

import (
	"context"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	auth "k8s.io/api/authentication/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
)

// RequestIssuer renews only the explicitly enrolled issuer, never an arbitrary SA.
// The successor must authenticate and pass the same effective permission review.
func RequestIssuer(ctx context.Context, client kubernetes.Interface, c config.Cluster, ca []byte, now time.Time) (Candidate, error) {
	var candidate Candidate
	policy, account := c.Provider.Renewal, c.Provider.ServiceAccount
	if c.Provider.Type != "SecretIssuer" || policy == nil || account == nil || c.Provider.LongLived == nil || *c.Provider.LongLived {
		return candidate, provider.Trust
	}
	expiration := policy.RequestedSeconds
	api := client.CoreV1().RESTClient()
	if api == nil {
		return candidate, provider.Trust
	}
	response := &auth.TokenRequest{}
	// The cluster workqueue owns backoff. Hidden HTTP retries must not consume the
	// source safety budget or issue extra successors after an ambiguous response.
	err := api.Post().Namespace(c.IdentityNamespace).Resource("serviceaccounts").Name(account.Name).
		SubResource("token").VersionedParams(&meta.CreateOptions{}, scheme.ParameterCodec).
		Body(&auth.TokenRequest{Spec: auth.TokenRequestSpec{Audiences: c.Audiences, ExpirationSeconds: &expiration}}).
		MaxRetries(0).Do(ctx).Into(response)
	if err != nil {
		return candidate, provider.Classify(err)
	}
	claims, err := credential.Parse(response.Status.Token)
	if err != nil || claims.Lifetime(now, time.Duration(policy.ClockSkewSeconds)*time.Second, policy.AcceptedMinSeconds, policy.AcceptedMaxSeconds) != nil ||
		!credential.SameSet(claims.Audience, c.Audiences) || claims.Subject != c.ExpectedIssuer.Username || claims.Kubernetes.Namespace != c.IdentityNamespace ||
		claims.Kubernetes.ServiceAccount.Name != account.Name || claims.Kubernetes.ServiceAccount.UID != account.UID || claims.Expires != response.Status.ExpirationTimestamp.Unix() {
		return candidate, provider.Auth
	}
	successor, err := Client(c.Endpoint, provider.IssuerCredential{Bearer: response.Status.Token, CA: ca})
	if err != nil {
		return candidate, err
	}
	if err := Issuer(ctx, successor, c); err != nil {
		return candidate, err
	}
	return Candidate{Token: response.Status.Token, CA: append([]byte(nil), ca...), Expires: response.Status.ExpirationTimestamp.Time}, nil
}
