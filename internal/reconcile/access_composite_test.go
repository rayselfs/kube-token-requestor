package reconcile

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

// The opt-in probe uses the same owned namespace and real publisher Secret.
func startAccessComposite(t *testing.T, ctx context.Context, namespace string) func() {
	t.Helper()
	if os.Getenv("REQUESTOR_ACCESS_COMPOSITE_RESULT") == "" {
		return func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(ctx, "python3", "../../integration/access-composite.py")
	cmd.Env = append(os.Environ(), "REQUESTOR_ACCESS_NAMESPACE="+namespace)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		ready <- scanner.Scan() && scanner.Text() == "ready"
		for scanner.Scan() {
		} // Do not expose credentials from a failed fixture.
		done <- cmd.Wait()
	}()
	finished := false
	t.Cleanup(func() {
		cancel()
		if !finished {
			<-done
		}
	})
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("local composite did not become ready")
		}
	case <-time.After(180 * time.Second):
		t.Fatal("local composite startup timed out")
	}
	return func() {
		t.Helper()
		err := <-done
		finished = true
		if err != nil {
			t.Fatal("local composite failed; inspect sanitized result")
		}
	}
}
