package issue

import (
	"context"
	"slices"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	authz "k8s.io/api/authorization/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Review the enrolled namespace's effective rules, including cluster-scoped bindings.
// This cannot discover arbitrary RoleBindings in other namespaces: operator review remains required.
func reviewPermissions(ctx context.Context, client kubernetes.Interface, c config.Cluster, consumer *config.Consumer) error {
	response, err := client.AuthorizationV1().SelfSubjectRulesReviews().Create(ctx, &authz.SelfSubjectRulesReview{Spec: authz.SelfSubjectRulesReviewSpec{Namespace: c.IdentityNamespace}}, meta.CreateOptions{})
	if err != nil {
		return provider.Classify(err)
	}
	if response.Status.Incomplete || response.Status.EvaluationError != "" {
		return provider.Auth
	}
	accounts := []string{}
	for _, consumer := range c.Consumers {
		accounts = append(accounts, consumer.ServiceAccount.Name)
	}
	if c.Provider.ServiceAccount != nil {
		accounts = append(accounts, c.Provider.ServiceAccount.Name)
	}
	for _, rule := range response.Status.ResourceRules {
		if len(rule.APIGroups) == 0 || len(rule.Resources) == 0 || len(rule.Verbs) == 0 {
			return provider.Auth
		}
		for _, group := range rule.APIGroups {
			for _, resource := range rule.Resources {
				for _, verb := range rule.Verbs {
					allowed := false
					if verb == "create" {
						allowed = group == "authentication.k8s.io" && resource == "selfsubjectreviews" || group == "authorization.k8s.io" && (resource == "selfsubjectaccessreviews" || resource == "selfsubjectrulesreviews")
						if consumer == nil && group == "" && resource == "serviceaccounts/token" {
							names := []string{}
							for _, consumer := range c.Consumers {
								names = append(names, consumer.ServiceAccount.Name)
							}
							allowed = namedOnly(rule.ResourceNames, names)
						}
					}
					if group == "" && resource == "namespaces" && verb == "get" {
						allowed = namedOnly(rule.ResourceNames, []string{"kube-system"})
					}
					if group == "" && resource == "serviceaccounts" && verb == "get" {
						allowed = namedOnly(rule.ResourceNames, accounts)
					}
					if consumer != nil {
						if group == "" && resource == "events" && (verb == "create" || verb == "patch") {
							allowed = true
						}
						if verb == "get" || verb == "list" || verb == "watch" {
							allowed = allowed || schedulingRead(group, resource)
						}
					}
					if !allowed {
						return provider.Auth
					}
				}
			}
		}
	}
	for _, rule := range response.Status.NonResourceRules {
		for _, verb := range rule.Verbs {
			if verb != "get" {
				return provider.Auth
			}
		}
		for _, path := range rule.NonResourceURLs {
			if !slices.Contains([]string{"/api", "/api/*", "/apis", "/apis/*", "/healthz", "/livez", "/openapi", "/openapi/*", "/readyz", "/version", "/version/", "/.well-known/openid-configuration", "/.well-known/openid-configuration/", "/openid/v1/jwks", "/openid/v1/jwks/"}, path) {
				return provider.Auth
			}
		}
	}
	return nil
}

func namedOnly(names, allowed []string) bool {
	if len(names) == 0 {
		return false
	}
	for _, name := range names {
		if !slices.Contains(allowed, name) {
			return false
		}
	}
	return true
}

func schedulingRead(group, resource string) bool {
	switch group {
	case "":
		return slices.Contains([]string{"nodes", "pods", "services", "namespaces", "endpoints", "replicationcontrollers", "persistentvolumes", "persistentvolumeclaims"}, resource)
	case "apps":
		return slices.Contains([]string{"daemonsets", "replicasets", "statefulsets", "deployments"}, resource)
	case "batch":
		return resource == "jobs"
	case "policy":
		return resource == "poddisruptionbudgets"
	case "storage.k8s.io":
		return slices.Contains([]string{"storageclasses", "csinodes", "csidrivers", "csistoragecapacities", "volumeattachments"}, resource)
	case "resource.k8s.io":
		return slices.Contains([]string{"resourceclaims", "resourceclaimtemplates", "resourceslices", "deviceclasses"}, resource)
	default:
		return false
	}
}
