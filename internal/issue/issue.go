package issue

import (
	"context"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	auth "k8s.io/api/authentication/v1"
	authz "k8s.io/api/authorization/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type Candidate struct {
	Token   string
	CA      []byte
	Expires time.Time
}

func Client(endpoint string, identity provider.IssuerCredential) (kubernetes.Interface, error) {
	if !config.APIEndpoint(endpoint) {
		return nil, provider.Trust
	}
	if _, err := credential.Parse(identity.Bearer); err != nil {
		return nil, provider.Auth
	}
	httpClient, err := provider.HTTP(identity.CA)
	if err != nil {
		return nil, err
	}
	config := &rest.Config{Host: endpoint, BearerToken: identity.Bearer, TLSClientConfig: rest.TLSClientConfig{CAData: identity.CA}, Timeout: 10 * time.Second, QPS: 2, Burst: 4, UserAgent: "kube-token-requestor", WarningHandler: rest.NoWarnings{}}
	// HTTP owns trust and redirect policy; rest owns bearer transport wrapping.
	transport, err := rest.HTTPWrappersForConfig(config, httpClient.Transport)
	if err != nil {
		return nil, provider.Trust
	}
	httpClient.Transport = transport
	client, err := kubernetes.NewForConfigAndClient(config, httpClient)
	if err != nil {
		return nil, provider.Trust
	}
	return client, nil
}

func Identity(ctx context.Context, client kubernetes.Interface, c config.Cluster, expected config.Principal) error {
	version, err := client.Discovery().ServerVersion()
	if err != nil {
		return provider.Classify(err)
	}
	if version.Major != "1" || (version.Minor != "34" && version.Minor != "35" && version.Minor != "36") {
		return provider.Trust
	}
	ns, err := client.CoreV1().Namespaces().Get(ctx, "kube-system", meta.GetOptions{})
	if err != nil {
		return provider.Classify(err)
	}
	if string(ns.UID) != c.KubeSystemUID {
		return provider.Trust
	}
	identity, err := client.AuthenticationV1().SelfSubjectReviews().Create(ctx, &auth.SelfSubjectReview{}, meta.CreateOptions{})
	if err != nil {
		return provider.Classify(err)
	}
	if identity.Status.UserInfo.Username != expected.Username || !credential.SameSet(identity.Status.UserInfo.Groups, expected.Groups) {
		return provider.Auth
	}
	return nil
}

func Permission(ctx context.Context, client kubernetes.Interface, attributes authz.ResourceAttributes, allowed bool) error {
	response, err := client.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authz.SelfSubjectAccessReview{Spec: authz.SelfSubjectAccessReviewSpec{ResourceAttributes: &attributes}}, meta.CreateOptions{})
	if err != nil {
		return provider.Classify(err)
	}
	if response.Status.EvaluationError != "" || response.Status.Allowed != allowed || (allowed && response.Status.Denied) {
		return provider.Auth
	}
	return nil
}

func NamedSA(ctx context.Context, client kubernetes.Interface, namespace string, account config.ServiceAccount) error {
	object, err := client.CoreV1().ServiceAccounts(namespace).Get(ctx, account.Name, meta.GetOptions{})
	if err != nil {
		return provider.Classify(err)
	}
	if string(object.UID) != account.UID {
		return provider.Trust
	}
	return nil
}

func Issuer(ctx context.Context, client kubernetes.Interface, c config.Cluster) error {
	if err := Identity(ctx, client, c, c.ExpectedIssuer); err != nil {
		return err
	}
	if err := reviewPermissions(ctx, client, c, nil); err != nil {
		return err
	}
	if c.Provider.ServiceAccount != nil {
		if err := NamedSA(ctx, client, c.IdentityNamespace, *c.Provider.ServiceAccount); err != nil {
			return err
		}
		if err := Permission(ctx, client, authz.ResourceAttributes{Namespace: c.IdentityNamespace, Verb: "create", Resource: "serviceaccounts", Subresource: "token", Name: c.Provider.ServiceAccount.Name}, false); err != nil {
			return err
		}
	}
	for _, consumer := range c.Consumers {
		if err := NamedSA(ctx, client, c.IdentityNamespace, consumer.ServiceAccount); err != nil {
			return err
		}
		if err := Permission(ctx, client, authz.ResourceAttributes{Namespace: c.IdentityNamespace, Verb: "create", Resource: "serviceaccounts", Subresource: "token", Name: consumer.ServiceAccount.Name}, true); err != nil {
			return err
		}
	}
	return denied(ctx, client, c.IdentityNamespace)
}

func denied(ctx context.Context, client kubernetes.Interface, namespace string) error {
	for _, resource := range []authz.ResourceAttributes{
		{Namespace: namespace, Verb: "get", Resource: "secrets"},
		{Namespace: namespace, Verb: "create", Resource: "serviceaccounts", Subresource: "token", Name: "unregistered-requestor-denial-probe"},
		{Namespace: namespace, Verb: "create", Group: "rbac.authorization.k8s.io", Resource: "rolebindings"},
		{Namespace: namespace, Verb: "patch", Group: "cluster.x-k8s.io", Resource: "machinedeployments"},
		{Verb: "patch", Resource: "nodes"},
	} {
		if err := Permission(ctx, client, resource, false); err != nil {
			return err
		}
	}
	return nil
}

func ValidateConsumer(ctx context.Context, client kubernetes.Interface, c config.Cluster, consumer config.Consumer) error {
	principal := config.Principal{Username: "system:serviceaccount:" + c.IdentityNamespace + ":" + consumer.ServiceAccount.Name, Groups: []string{"system:serviceaccounts", "system:serviceaccounts:" + c.IdentityNamespace, "system:authenticated"}}
	if err := Identity(ctx, client, c, principal); err != nil {
		return err
	}
	if err := reviewPermissions(ctx, client, c, &consumer); err != nil {
		return err
	}
	if err := NamedSA(ctx, client, c.IdentityNamespace, consumer.ServiceAccount); err != nil {
		return err
	}
	for _, resource := range []authz.ResourceAttributes{
		{Verb: "list", Resource: "nodes"}, {Verb: "list", Resource: "pods"}, {Verb: "list", Resource: "services"},
		{Verb: "list", Group: "apps", Resource: "daemonsets"}, {Verb: "list", Group: "policy", Resource: "poddisruptionbudgets"},
		{Namespace: c.IdentityNamespace, Verb: "create", Resource: "events"},
	} {
		if err := Permission(ctx, client, resource, true); err != nil {
			return err
		}
	}
	if err := Permission(ctx, client, authz.ResourceAttributes{Namespace: c.IdentityNamespace, Verb: "create", Resource: "serviceaccounts", Subresource: "token", Name: consumer.ServiceAccount.Name}, false); err != nil {
		return err
	}
	return denied(ctx, client, c.IdentityNamespace)
}

func Request(ctx context.Context, client kubernetes.Interface, c config.Cluster, consumer config.Consumer, ca []byte, now time.Time) (Candidate, error) {
	var candidate Candidate
	expiration := c.Lifetime.RequestedSeconds
	response, err := client.CoreV1().ServiceAccounts(c.IdentityNamespace).CreateToken(ctx, consumer.ServiceAccount.Name, &auth.TokenRequest{Spec: auth.TokenRequestSpec{Audiences: c.Audiences, ExpirationSeconds: &expiration}}, meta.CreateOptions{})
	if err != nil {
		return candidate, provider.Classify(err)
	}
	claims, err := credential.Parse(response.Status.Token)
	if err != nil || claims.Lifetime(now, time.Duration(c.Lifetime.ClockSkewSeconds)*time.Second, c.Lifetime.AcceptedMinSeconds, c.Lifetime.AcceptedMaxSeconds) != nil ||
		!credential.SameSet(claims.Audience, c.Audiences) || claims.Subject != "system:serviceaccount:"+c.IdentityNamespace+":"+consumer.ServiceAccount.Name ||
		claims.Kubernetes.Namespace != c.IdentityNamespace || claims.Kubernetes.ServiceAccount.Name != consumer.ServiceAccount.Name || claims.Kubernetes.ServiceAccount.UID != consumer.ServiceAccount.UID ||
		claims.Expires != response.Status.ExpirationTimestamp.Unix() {
		return candidate, provider.Auth
	}
	consumerClient, err := Client(c.Endpoint, provider.IssuerCredential{Bearer: response.Status.Token, CA: ca})
	if err != nil {
		return candidate, err
	}
	if err := ValidateConsumer(ctx, consumerClient, c, consumer); err != nil {
		return candidate, err
	}
	candidate = Candidate{Token: response.Status.Token, CA: append([]byte(nil), ca...), Expires: response.Status.ExpirationTimestamp.Time}
	return candidate, nil
}
