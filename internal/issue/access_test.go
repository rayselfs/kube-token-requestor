package issue

import (
	"context"
	"github.com/rayselfs/kube-token-requestor/internal/config"
	authz "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	kt "k8s.io/client-go/testing"
	"testing"
)

func TestAccessRules(t *testing.T) {
	consumer := config.Consumer{Access: &config.Access{Users: []string{"reader@example.invalid"}, Groups: []string{"readers"}}}
	for _, tc := range []struct {
		resource, verb, name string
		ok                   bool
	}{
		{"users", "impersonate", "reader@example.invalid", true}, {"groups", "impersonate", "readers", true},
		{"users", "impersonate", "", false}, {"users", "impersonate", "other", false}, {"groups", "impersonate", "system:masters", false},
		{"pods", "list", "", false}, {"events", "create", "", false}, {"serviceaccounts", "impersonate", "reader", false},
		{"users", "*", "reader@example.invalid", false}, {"secrets", "get", "output", false},
	} {
		t.Run(tc.resource+tc.verb+tc.name, func(t *testing.T) {
			client := fake.NewClientset()
			names := []string{}
			if tc.name != "" {
				names = append(names, tc.name)
			}
			client.PrependReactor("create", "selfsubjectrulesreviews", func(kt.Action) (bool, runtime.Object, error) {
				return true, &authz.SelfSubjectRulesReview{Status: authz.SubjectRulesReviewStatus{ResourceRules: []authz.ResourceRule{{APIGroups: []string{""}, Resources: []string{tc.resource}, Verbs: []string{tc.verb}, ResourceNames: names}}}}, nil
			})
			if (reviewPermissions(context.Background(), client, config.Cluster{}, &consumer) == nil) != tc.ok {
				t.Fatal("permission boundary")
			}
		})
	}
}
