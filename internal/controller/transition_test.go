package controller

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"k8s.io/client-go/kubernetes/fake"
)

func TestRegistryCannotRebindExistingIdentity(t *testing.T) {
	data, err := os.ReadFile("../../examples/registry.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*config.Registry)
	}{
		{"child UID", func(r *config.Registry) { r.Clusters[0].KubeSystemUID = r.Clusters[1].KubeSystemUID }},
		{"child endpoint", func(r *config.Registry) { r.Clusters[0].Endpoint = r.Clusters[1].Endpoint }},
		{"CA trust", func(r *config.Registry) { r.Clusters[0].CASHA256 = strings.Repeat("3", 64) }},
		{"source namespace", func(r *config.Registry) { r.Clusters[0].IdentityNamespace = "other" }},
		{"output UID", func(r *config.Registry) {
			r.Clusters[0].Consumers[0].Secret.UID = r.Clusters[0].Consumers[1].Secret.UID
		}},
		{"CA deployment UID", func(r *config.Registry) {
			r.Clusters[0].Consumers[0].CADeployment.UID = r.Clusters[0].Consumers[1].CADeployment.UID
		}},
		{"consumer SA", func(r *config.Registry) {
			r.Clusters[0].Consumers[0].ServiceAccount = r.Clusters[0].Consumers[1].ServiceAccount
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old, err := config.Parse(strings.NewReader(string(data)))
			if err != nil {
				t.Fatal(err)
			}
			next, err := config.Parse(strings.NewReader(string(data)))
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(next)
			client := fake.NewClientset()
			r := &runtime{registry: old, client: client}
			if err := r.transition(context.Background(), next); err != provider.Trust {
				t.Fatal("unsafe identity rebind accepted")
			}
			if len(client.Actions()) != 0 {
				t.Fatal("API write before identity guard")
			}
		})
	}
}
