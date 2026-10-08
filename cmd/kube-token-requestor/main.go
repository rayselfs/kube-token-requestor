package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/controller"
	"github.com/rayselfs/kube-token-requestor/internal/observe"
)

var version = "unreleased"

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

func main() {
	if len(os.Args) > 1 && os.Args[1] == "run" {
		os.Exit(serve(os.Args[2:], os.Stderr))
	}
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func serve(args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var opts controller.Options
	flags.StringVar(&opts.Namespace, "namespace", "", "controller namespace")
	flags.StringVar(&opts.Registry, "registry", "kube-token-requestor-registry", "named registry")
	flags.StringVar(&opts.Status, "status", "kube-token-requestor-status", "named status")
	flags.StringVar(&opts.Lease, "lease", "kube-token-requestor", "named lease")
	flags.StringVar(&opts.Identity, "identity", os.Getenv("POD_UID"), "leader identity")
	flags.StringVar(&opts.SubjectRoot, "subject-root", "/var/run/token-requestor/subjects", "projected token root")
	listen := flags.String("listen", ":8080", "internal health/metrics address")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "invalid runtime arguments")
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	metrics := &observe.Metrics{}
	server := &http.Server{Addr: *listen, Handler: metrics.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	errors := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errors <- err
			cancel()
		}
	}()
	err := controller.Run(ctx, opts, metrics)
	shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	_ = server.Shutdown(shutdown)
	select {
	case <-errors:
		fmt.Fprintln(stderr, "internal HTTP listener failed")
		return 1
	default:
	}
	if err != nil {
		fmt.Fprintln(stderr, "controller stopped:", err)
		return 1
	}
	return 0
}
