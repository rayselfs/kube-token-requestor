package config

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestAccessBoundaries(t *testing.T) {
	data, err := os.ReadFile("../../examples/access-registry.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Consumer)
	}{
		{"valid", func(c *Consumer) {}},
		{"wildcard", func(c *Consumer) { c.Access.Users = []string{"*"} }},
		{"system", func(c *Consumer) { c.Access.Groups = []string{"system:masters"} }},
		{"CA", func(c *Consumer) { c.CADeployment.Name = "ca" }},
		{"stop", func(c *Consumer) { c.ReloadPolicy = "StopStart" }},
		{"profile", func(c *Consumer) { c.PermissionProfile = "ca-read-events" }},
		{"empty", func(c *Consumer) { c.Access.Users = nil }},
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
					t.Fatal("roundtrip", err)
				}
			}
		})
	}
}
