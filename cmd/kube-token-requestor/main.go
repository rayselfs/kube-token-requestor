package main

import (
	"fmt"
	"io"
	"os"

	"github.com/rayselfs/kube-token-requestor/internal/config"
)

const version = "unreleased"

func run(args []string, input io.Reader, output, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "version" {
		fmt.Fprintln(output, version)
		return 0
	}
	if len(args) != 1 || args[0] != "validate-config" {
		fmt.Fprintln(stderr, "usage: kube-token-requestor {validate-config|version}; registry is read from stdin")
		return 2
	}
	registry, err := config.Parse(input)
	if err != nil {
		fmt.Fprintln(stderr, "registry validation failed")
		return 1
	}
	consumers := 0
	for _, cluster := range registry.Clusters {
		consumers += len(cluster.Consumers)
	}
	fmt.Fprintf(output, "valid registry: %d clusters, %d consumers\n", len(registry.Clusters), consumers)
	return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }
