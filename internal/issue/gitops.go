package issue

import (
	"context"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	authz "k8s.io/api/authorization/v1"
	"k8s.io/client-go/kubernetes"
)

func BoundClaims(claims credential.Claims, consumer config.Consumer) bool {
	if !consumer.IsGitOps() {
		return true
	}
	ref := consumer.GitOps.BoundSecret
	return claims.Kubernetes.Secret.Name == ref.Name && claims.Kubernetes.Secret.UID == ref.UID
}

func validateGitOps(ctx context.Context, client kubernetes.Interface, c config.Cluster, consumer config.Consumer) error {
	g := consumer.GitOps
	for _, verb := range []string{"get", "list", "watch", "patch", "update"} {
		name := ""
		if verb == "get" || verb == "patch" || verb == "update" {
			name = g.ConfigMap
		}
		if err := Permission(ctx, client, authz.ResourceAttributes{Namespace: g.Namespace, Resource: "configmaps", Name: name, Verb: verb}, true); err != nil {
			return err
		}
	}
	other := "token-requestor-deny-probe"
	if other == g.ConfigMap {
		other += "-other"
	}
	for _, a := range []authz.ResourceAttributes{
		{Namespace: g.Namespace, Resource: "configmaps", Name: other, Verb: "patch"},
		{Namespace: g.Namespace, Resource: "configmaps", Name: g.ConfigMap, Verb: "delete"},
		{Namespace: g.Namespace, Resource: "configmaps", Verb: "create"},
		{Namespace: g.Namespace, Resource: "secrets", Name: g.BoundSecret.Name, Verb: "get"},
		{Namespace: c.IdentityNamespace, Resource: "serviceaccounts", Subresource: "token", Name: consumer.ServiceAccount.Name, Verb: "create"},
	} {
		if err := Permission(ctx, client, a, false); err != nil {
			return err
		}
	}
	return denied(ctx, client, c.IdentityNamespace)
}
