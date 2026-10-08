package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/issue"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/publish"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
)

// revokeIssuer replaces a synthetic source only after candidate validation, then revokes its predecessor.
func revokeIssuer(root, path string) (result error) {
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
	if a.ID != "child-a" || b.ID != "child-b" || a.Provider.Type != "SecretIssuer" || a.Provider.Secret == nil || a.Provider.ServiceAccount == nil || len(a.Consumers) != 2 || len(b.Consumers) != 1 || a.Lifetime.RenewBeforeSeconds != 570 {
		return provider.Trust
	}
	management, _, err := local(root, "management")
	if err != nil {
		return err
	}
	child, _, err := local(root, "child-a")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for role, expected := range map[string]string{"management": values.Registry.ManagementUID, "child-a": a.KubeSystemUID, "child-b": b.KubeSystemUID} {
		client, _, err := local(root, role)
		if err != nil {
			return err
		}
		ns, err := client.CoreV1().Namespaces().Get(ctx, "kube-system", meta.GetOptions{})
		if err != nil || string(ns.UID) != expected {
			return provider.Trust
		}
	}
	cfg, err := clientcmd.LoadFromFile(root + "/child-a")
	if err != nil {
		return provider.Trust
	}
	a.Endpoint = cfg.Clusters["kind-requestor-child-a"].Server
	ref := *a.Provider.Secret
	source, err := provider.ReadSecret(ctx, management, ref, "ca.crt", "token")
	if err != nil {
		return err
	}
	old, err := child.CoreV1().Secrets(a.IdentityNamespace).Get(ctx, "issuer-token", meta.GetOptions{})
	if err != nil || old.Type != core.SecretTypeServiceAccountToken || old.Annotations[core.ServiceAccountUIDKey] != a.Provider.ServiceAccount.UID || !bytes.Equal(old.Data["token"], source.Data["token"]) {
		return provider.Trust
	}
	oldClient, err := issue.Client(a.Endpoint, provider.IssuerCredential{Bearer: string(source.Data["token"]), CA: source.Data["ca.crt"]})
	if err != nil {
		return err
	}
	if err := issue.Issuer(ctx, oldClient, a); err != nil {
		return err
	}
	pods, err := management.CoreV1().Pods("requestor-test").List(ctx, meta.ListOptions{LabelSelector: "app=" + a.Consumers[0].ID})
	if err != nil || len(pods.Items) != 1 || len(pods.Items[0].Status.ContainerStatuses) != 1 || !pods.Items[0].Status.ContainerStatuses[0].Ready {
		return provider.Trust
	}
	podUID := pods.Items[0].UID
	beforeA, err := publish.Read(ctx, management, a.Consumers[0])
	if err != nil {
		return err
	}
	beforeB, err := publish.Read(ctx, management, b.Consumers[0])
	if err != nil {
		return err
	}
	candidate, err := child.CoreV1().Secrets(a.IdentityNamespace).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{GenerateName: "issuer-replacement-", Annotations: map[string]string{core.ServiceAccountNameKey: a.Provider.ServiceAccount.Name}}, Type: core.SecretTypeServiceAccountToken}, meta.CreateOptions{})
	if err != nil {
		return provider.Classify(err)
	}
	candidateUID := candidate.UID
	retainCandidate := false
	defer func() {
		if retainCandidate {
			return
		} // Preserve possibly adopted credentials after an indeterminate source write.
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		if err := child.CoreV1().Secrets(a.IdentityNamespace).Delete(cleanup, candidate.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &candidateUID}}); err != nil {
			result = provider.Classify(err)
		}
	}()
	ready := false
	for range 40 {
		candidate, err = child.CoreV1().Secrets(a.IdentityNamespace).Get(ctx, candidate.Name, meta.GetOptions{})
		if err != nil || candidate.UID != candidateUID {
			return provider.Trust
		}
		if len(candidate.Data["token"]) > 0 {
			ready = true
			break
		}
		if err := waitLocal(ctx, time.Second); err != nil {
			return err
		}
	}
	if !ready || candidate.Annotations[core.ServiceAccountUIDKey] != a.Provider.ServiceAccount.UID {
		return provider.Trust
	}
	candidateClient, err := issue.Client(a.Endpoint, provider.IssuerCredential{Bearer: string(candidate.Data["token"]), CA: source.Data["ca.crt"]})
	if err != nil {
		return err
	}
	if err := issue.Issuer(ctx, candidateClient, a); err != nil {
		return err
	}
	patch, _ := json.Marshal([]map[string]any{{"op": "test", "path": "/metadata/uid", "value": ref.UID}, {"op": "test", "path": "/metadata/resourceVersion", "value": source.ResourceVersion}, {"op": "replace", "path": "/data/token", "value": candidate.Data["token"]}, {"op": "add", "path": "/metadata/annotations/token-requestor.io~1rotated-at", "value": time.Now().UTC().Format(time.RFC3339)}})
	// A transport error cannot prove the CAS write was not applied. Keep the candidate from here.
	retainCandidate = true
	_, err = management.CoreV1().Secrets(ref.Namespace).Patch(ctx, ref.Name, types.JSONPatchType, patch, meta.PatchOptions{})
	if err != nil {
		return provider.Classify(err)
	}
	current, err := provider.ReadSecret(ctx, management, ref, "ca.crt", "token")
	if err != nil || !bytes.Equal(current.Data["token"], candidate.Data["token"]) {
		return provider.Trust
	}
	if err := child.CoreV1().Secrets(a.IdentityNamespace).Delete(ctx, old.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &old.UID, ResourceVersion: &old.ResourceVersion}}); err != nil {
		return provider.Classify(err)
	}
	rejected := false
	for range 60 {
		err := issue.Issuer(ctx, oldClient, a)
		if err == provider.Auth {
			rejected = true
			break
		}
		if err != nil {
			return err
		}
		if err := waitLocal(ctx, 2*time.Second); err != nil {
			return err
		}
	}
	if !rejected {
		return provider.Trust
	}
	recovered := false
	for range 45 {
		afterA, err := publish.Read(ctx, management, a.Consumers[0])
		if err != nil {
			return err
		}
		afterB, err := publish.Read(ctx, management, b.Consumers[0])
		if err != nil {
			return err
		}
		if credential.Hash(afterA.Data["token"]) != credential.Hash(beforeA.Data["token"]) && credential.Hash(afterB.Data["token"]) != credential.Hash(beforeB.Data["token"]) {
			recovered = true
			break
		}
		if err := waitLocal(ctx, 2*time.Second); err != nil {
			return err
		}
	}
	if !recovered {
		return provider.Trust
	}
	pods, err = management.CoreV1().Pods("requestor-test").List(ctx, meta.ListOptions{LabelSelector: "app=" + a.Consumers[0].ID})
	if err != nil || len(pods.Items) != 1 || pods.Items[0].UID != podUID || len(pods.Items[0].Status.ContainerStatuses) != 1 || !pods.Items[0].Status.ContainerStatuses[0].Ready || pods.Items[0].Status.ContainerStatuses[0].RestartCount != 0 {
		return provider.Trust
	}
	if err := assert(root, path, false); err != nil {
		return err
	}
	fmt.Println("local issuer replacement passed: restricted candidate adopted; predecessor API authentication rejected; both children rotated; CA Pod retained")
	return nil
}
