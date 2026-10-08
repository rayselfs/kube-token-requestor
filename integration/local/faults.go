package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/publish"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// faults changes annotations only on pinned synthetic fixtures. Credentials stay in memory.
func faults(root, path string) (result error) {
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
	management, _, err := local(root, "management")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	uid, err := management.CoreV1().Namespaces().Get(ctx, "kube-system", meta.GetOptions{})
	if err != nil || string(uid.UID) != values.Registry.ManagementUID {
		return provider.Trust
	}
	for _, c := range values.Registry.Clusters {
		child, _, err := local(root, c.ID)
		if err != nil {
			return err
		}
		uid, err := child.CoreV1().Namespaces().Get(ctx, "kube-system", meta.GetOptions{})
		if err != nil || string(uid.UID) != c.KubeSystemUID {
			return provider.Trust
		}
		if c.Provider.Type != "SecretIssuer" || c.Provider.Secret == nil || c.Lifetime.RequestedSeconds != 600 || c.Lifetime.RenewBeforeSeconds != 570 {
			return provider.Trust
		}
	}
	a, b := values.Registry.Clusters[0], values.Registry.Clusters[1]
	if a.ID != "child-a" || b.ID != "child-b" || len(a.Consumers) != 2 || len(b.Consumers) != 1 {
		return provider.Trust
	}
	for _, c := range a.Consumers {
		d, err := management.AppsV1().Deployments(c.CADeployment.Namespace).Get(ctx, c.CADeployment.Name, meta.GetOptions{})
		if err != nil || string(d.UID) != c.CADeployment.UID || d.Spec.Replicas == nil {
			return provider.Trust
		}
		if c.ID == a.Consumers[1].ID && *d.Spec.Replicas != 0 {
			return provider.Trust
		}
	}
	hash := func(c config.Consumer) (string, error) {
		s, err := management.CoreV1().Secrets(c.Secret.Namespace).Get(ctx, c.Secret.Name, meta.GetOptions{})
		if err != nil || string(s.UID) != c.Secret.UID {
			return "", provider.Trust
		}
		return credential.Hash(s.Data["token"]), nil
	}
	// A full issuer outage is isolated to child-a while child-b continues rotating.
	source, err := management.CoreV1().Secrets(a.Provider.Secret.Namespace).Get(ctx, a.Provider.Secret.Name, meta.GetOptions{})
	if err != nil || string(source.UID) != a.Provider.Secret.UID {
		return provider.Trust
	}
	old := source.Annotations["token-requestor.io/rotated-at"]
	invalid := time.Now().Add(-100 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if err := fixtureAnnotation(ctx, management, *a.Provider.Secret, "token-requestor.io/rotated-at", old, invalid); err != nil {
		return err
	}
	restoreSource := func() error {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		return fixtureAnnotation(cleanup, management, *a.Provider.Secret, "token-requestor.io/rotated-at", invalid, old)
	}
	sourceRestored := false
	defer func() {
		if !sourceRestored {
			if err := restoreSource(); err != nil {
				fmt.Println("local fixture source restoration requires review")
				result = err
			}
		}
	}()
	// Allow any pre-fault acquisition to finish before measuring a stable blocked interval.
	if err := waitLocal(ctx, 35*time.Second); err != nil {
		return err
	}
	aBefore, err := hash(a.Consumers[0])
	if err != nil {
		return err
	}
	bBefore, err := hash(b.Consumers[0])
	if err != nil {
		return err
	}
	if err := waitLocal(ctx, 65*time.Second); err != nil {
		return err
	}
	aAfter, err := hash(a.Consumers[0])
	if err != nil {
		return err
	}
	bAfter, err := hash(b.Consumers[0])
	if err != nil {
		return err
	}
	if aBefore != aAfter || bBefore == bAfter {
		return provider.Trust
	}
	if err := restoreSource(); err != nil {
		return err
	}
	sourceRestored = true
	if err := waitLocal(ctx, 150*time.Second); err != nil {
		return err
	}
	aRecovered, err := hash(a.Consumers[0])
	if err != nil || aRecovered == aAfter {
		return provider.Trust
	}
	fmt.Println("local issuer outage passed: affected child froze, healthy child rotated, source replacement recovered")
	// Corrupt only the stopped consumer's ownership marker. Never change an active CA's binding.
	consumer := a.Consumers[1]
	foreign := "local-foreign-writer"
	if err := fixtureAnnotation(ctx, management, consumer.Secret, publish.Owner, consumer.ID, foreign); err != nil {
		return err
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		if err := fixtureAnnotation(cleanup, management, consumer.Secret, publish.Owner, foreign, consumer.ID); err != nil {
			fmt.Println("local fixture output restoration requires review")
			result = err
		}
	}()
	blockedBefore, err := hash(consumer)
	if err != nil {
		return err
	}
	siblingBefore, err := hash(a.Consumers[0])
	if err != nil {
		return err
	}
	if err := waitLocal(ctx, 65*time.Second); err != nil {
		return err
	}
	blockedAfter, err := hash(consumer)
	if err != nil {
		return err
	}
	siblingAfter, err := hash(a.Consumers[0])
	if err != nil {
		return err
	}
	if blockedBefore != blockedAfter || siblingBefore == siblingAfter {
		return provider.Trust
	}
	fmt.Println("local consumer isolation passed: foreign-owned stopped output retained; sibling continued rotating")
	return nil
}

func fixtureAnnotation(ctx context.Context, client kubernetes.Interface, ref config.Ref, key, before, after string) error {
	s, err := client.CoreV1().Secrets(ref.Namespace).Get(ctx, ref.Name, meta.GetOptions{})
	if err != nil || string(s.UID) != ref.UID {
		return provider.Trust
	}
	if s.Annotations[key] == after {
		return nil
	}
	if s.Annotations[key] != before {
		return provider.Conflict
	}
	path := "/metadata/annotations/" + strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
	patch, _ := json.Marshal([]map[string]any{
		{"op": "test", "path": "/metadata/uid", "value": ref.UID},
		{"op": "test", "path": "/metadata/resourceVersion", "value": s.ResourceVersion},
		{"op": "test", "path": path, "value": before},
		{"op": "replace", "path": path, "value": after},
	})
	_, err = client.CoreV1().Secrets(ref.Namespace).Patch(ctx, ref.Name, types.JSONPatchType, patch, meta.PatchOptions{})
	return provider.Classify(err)
}
func waitLocal(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return provider.Transport
	case <-timer.C:
		return nil
	}
}
