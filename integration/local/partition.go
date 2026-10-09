package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// partition pauses only a verified synthetic child kind node. It never changes API resources.
func partition(root, path string) (result error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return provider.Trust
	}
	var values struct {
		Registry config.Registry `json:"registry"`
	}
	if json.Unmarshal(data, &values) != nil || values.Registry.Validate() != nil || len(values.Registry.Clusters) != 2 {
		return provider.Trust
	}
	a, b := values.Registry.Clusters[0], values.Registry.Clusters[1]
	if a.ID != "child-a" || b.ID != "child-b" || len(a.Consumers) != 2 || len(b.Consumers) != 1 {
		return provider.Trust
	}
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Minute)
	defer cancel()
	management, _, err := local(root, "management")
	if err != nil {
		return err
	}
	system, err := management.CoreV1().Namespaces().Get(ctx, "kube-system", meta.GetOptions{})
	if err != nil || string(system.UID) != values.Registry.ManagementUID {
		return provider.Trust
	}
	for _, c := range values.Registry.Clusters {
		client, _, err := local(root, c.ID)
		if err != nil {
			return err
		}
		system, err := client.CoreV1().Namespaces().Get(ctx, "kube-system", meta.GetOptions{})
		if err != nil || string(system.UID) != c.KubeSystemUID || c.Provider.Type != "SecretIssuer" || c.Lifetime.RequestedSeconds != 600 || c.Lifetime.RenewBeforeSeconds != 570 {
			return provider.Trust
		}
	}
	output := func(c config.Consumer) (string, time.Time, error) {
		s, err := management.CoreV1().Secrets(c.Secret.Namespace).Get(ctx, c.Secret.Name, meta.GetOptions{})
		if err != nil || string(s.UID) != c.Secret.UID {
			return "", time.Time{}, provider.Trust
		}
		claims, err := credential.Parse(string(s.Data["token"]))
		if err != nil {
			return "", time.Time{}, provider.Trust
		}
		return credential.Hash(s.Data["token"]), time.Unix(claims.Expires, 0), nil
	}
	// Begin with enough actual remaining lifetime to separate transport failure from expiry.
	fresh := false
	for attempt := 0; attempt < 20; attempt++ {
		_, expires, err := output(a.Consumers[0])
		if err != nil {
			return err
		}
		if time.Until(expires) >= 8*time.Minute {
			fresh = true
			break
		}
		if err := waitLocal(ctx, 5*time.Second); err != nil {
			return err
		}
	}
	if !fresh {
		return provider.Trust
	}
	container := "requestor-child-a-control-plane"
	inspect := exec.CommandContext(ctx, "docker", "inspect", "--format", `{{index .Config.Labels "io.x-k8s.kind.cluster"}} {{index .Config.Labels "io.x-k8s.kind.role"}} {{.State.Paused}}`, container)
	inspected, err := inspect.Output()
	if err != nil || strings.TrimSpace(string(inspected)) != "requestor-child-a control-plane false" {
		return provider.Trust
	}
	if _, err := exec.CommandContext(ctx, "docker", "pause", container).Output(); err != nil {
		return provider.Transport
	}
	fmt.Println("synthetic child API paused; starting five-minute isolation observation")
	restored := false
	restore := func() error {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		if _, err := exec.CommandContext(cleanup, "docker", "unpause", container).Output(); err != nil {
			return provider.Transport
		}
		return nil
	}
	defer func() {
		if !restored {
			if err := restore(); err != nil {
				result = err
				fmt.Println("synthetic child container restoration requires review")
			}
		}
	}()
	// Drain pre-partition requests before asserting the publication freeze.
	if err := waitLocal(ctx, 35*time.Second); err != nil {
		return err
	}
	blocked, _, err := output(a.Consumers[0])
	if err != nil {
		return err
	}
	healthy, _, err := output(b.Consumers[0])
	if err != nil {
		return err
	}
	rotations := 0
	for elapsed := time.Duration(35) * time.Second; elapsed < 5*time.Minute; elapsed += 15 * time.Second {
		if err := waitLocal(ctx, min(15*time.Second, 5*time.Minute-elapsed)); err != nil {
			return err
		}
		current, _, err := output(a.Consumers[0])
		if err != nil || current != blocked {
			return provider.Trust
		}
		current, _, err = output(b.Consumers[0])
		if err != nil {
			return err
		}
		if current != healthy {
			rotations++
			healthy = current
		}
	}
	if rotations < 2 {
		return provider.Trust
	}
	fmt.Printf("synthetic child isolation observed %d healthy sibling rotations; restoring paused API\n", rotations)
	if err := restore(); err != nil {
		return err
	}
	restored = true
	recovered := false
	for attempt := 0; attempt < 30; attempt++ {
		current, _, err := output(a.Consumers[0])
		if err != nil {
			return err
		}
		if current != blocked {
			recovered = true
			break
		}
		if err := waitLocal(ctx, 5*time.Second); err != nil {
			return err
		}
	}
	if !recovered {
		return provider.Transport
	}
	child, _, err := local(root, "child-a")
	if err != nil {
		return err
	}
	system, err = child.CoreV1().Namespaces().Get(ctx, "kube-system", meta.GetOptions{})
	if err != nil || string(system.UID) != a.KubeSystemUID {
		return provider.Trust
	}
	fmt.Println("local child API partition passed: five-minute publication freeze, healthy sibling rotations and same-child recovery")
	return nil
}
