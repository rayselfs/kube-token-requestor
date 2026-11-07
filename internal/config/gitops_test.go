package config

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestGitOpsBoundaries(t *testing.T) {
	data, err := os.ReadFile("../../examples/gitops-registry.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Consumer)
	}{
		{"valid", func(c *Consumer) {}},
		{"access", func(c *Consumer) { c.Access = &Access{Users: []string{"reader"}} }},
		{"wildcard", func(c *Consumer) { c.GitOps.ConfigMap = "*" }},
		{"foreign-namespace", func(c *Consumer) { c.GitOps.Namespace = "other" }},
		{"foreign-lease", func(c *Consumer) { c.GitOps.BoundSecret.Namespace = "other" }},
		{"missing-lease", func(c *Consumer) { c.GitOps.BoundSecret.UID = "" }},
		{"ca", func(c *Consumer) { c.CADeployment.Name = "ca" }},
		{"reload", func(c *Consumer) { c.ReloadPolicy = "StopStart" }},
		{"profile", func(c *Consumer) { c.PermissionProfile = "access-impersonation" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Parse(strings.NewReader(string(data)))
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(&r.Clusters[0].Consumers[0])
			if (r.Validate() == nil) != (tc.name == "valid") {
				t.Fatal("boundary")
			}
			if tc.name == "valid" {
				b, _ := json.Marshal(r)
				if _, err := Parse(strings.NewReader(string(b))); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestGitOpsRejectsSharedRevocationLease(t *testing.T) {
	data, err := os.ReadFile("../../examples/gitops-registry.json")
	if err != nil {
		t.Fatal(err)
	}
	r, err := Parse(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	other := r.Clusters[0].Consumers[0]
	other.ID = "other"
	other.ServiceAccount.Name = "other"
	other.Secret.Name = "other"
	r.Clusters[0].Consumers = append(r.Clusters[0].Consumers, other)
	if r.Validate() == nil {
		t.Fatal("shared revocation lease accepted")
	}
	copyGitOps := *other.GitOps
	r.Clusters[0].Consumers[1].GitOps = &copyGitOps
	r.Clusters[0].Consumers[1].GitOps.BoundSecret.Name = "other"
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
}
