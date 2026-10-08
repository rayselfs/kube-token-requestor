package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestCLI(t *testing.T) {
	data, err := os.ReadFile("../../examples/registry.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		args  []string
		input string
		code  int
	}{
		{"valid", []string{"validate-config"}, string(data), 0},
		{"invalid", []string{"validate-config"}, `{"token":"sensitive-canary"}`, 1},
		{"version", []string{"version"}, "", 0},
		{"no command", nil, "", 2},
		{"runtime not implemented", []string{"run"}, "", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, stderr bytes.Buffer
			if code := run(tc.args, strings.NewReader(tc.input), &out, &stderr); code != tc.code {
				t.Fatalf("code %d", code)
			}
			if strings.Contains(out.String()+stderr.String(), "sensitive-canary") {
				t.Fatal("credential leaked")
			}
		})
	}
}
