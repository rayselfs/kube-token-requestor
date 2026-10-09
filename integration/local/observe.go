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
	"github.com/rayselfs/kube-token-requestor/internal/issue"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/publish"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
)

// observe keeps credentials in memory and emits only synthetic acceptance summaries.
func observe(root, path string, duration time.Duration) error {
	return observeProgress(root, path, duration, nil)
}

func observeProgress(root, path string, duration time.Duration, progress func(int, bool, string) error) error {
	if duration < 13*time.Minute || duration > 49*time.Hour {
		return provider.Trust
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return provider.Trust
	}
	var values struct {
		Registry config.Registry `json:"registry"`
	}
	if json.Unmarshal(data, &values) != nil {
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
	finishAt := time.Now().Add(duration)
	finish := time.NewTimer(duration)
	defer finish.Stop()
	// Observation completion must not cancel a final in-flight identity/log request.
	ctx, cancel := context.WithTimeout(context.Background(), duration+time.Minute)
	defer cancel()
	c := values.Registry.Clusters[0]
	consumer := c.Consumers[0]
	cfg, err := clientcmd.LoadFromFile(root + "/child-a")
	if err != nil {
		return provider.Trust
	}
	c.Endpoint = cfg.Clusters["kind-requestor-child-a"].Server
	uid, err := management.CoreV1().Namespaces().Get(ctx, "kube-system", meta.GetOptions{})
	if err != nil || string(uid.UID) != values.Registry.ManagementUID {
		return provider.Trust
	}
	uid, err = child.CoreV1().Namespaces().Get(ctx, "kube-system", meta.GetOptions{})
	if err != nil || string(uid.UID) != c.KubeSystemUID {
		return provider.Trust
	}
	first, err := publish.Read(ctx, management, consumer)
	if err != nil {
		return err
	}
	oldToken := string(first.Data["token"])
	oldExpiry := publish.StoredExpiry(first, c, consumer)
	oldClient, err := issue.Client(c.Endpoint, provider.IssuerCredential{Bearer: oldToken, CA: first.Data["ca.crt"]})
	if err != nil {
		return err
	}
	var podUID string
	lastHash := credential.Hash(first.Data["token"])
	rotations := 0
	oldRejected := false
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		if !time.Now().Before(finishAt) {
			return finishObservation(rotations, oldRejected)
		}
		pods, err := management.CoreV1().Pods(consumer.CADeployment.Namespace).List(ctx, meta.ListOptions{LabelSelector: "app=" + consumer.ID})
		if err != nil || len(pods.Items) != 1 {
			return provider.Trust
		}
		pod := pods.Items[0]
		if podUID == "" {
			podUID = string(pod.UID)
		}
		if string(pod.UID) != podUID || len(pod.Status.ContainerStatuses) != 1 || !pod.Status.ContainerStatuses[0].Ready || pod.Status.ContainerStatuses[0].RestartCount != 0 {
			return provider.Trust
		}
		current, err := publish.Read(ctx, management, consumer)
		if err != nil {
			return err
		}
		hash := credential.Hash(current.Data["token"])
		if hash != lastHash {
			rotations++
			lastHash = hash
		}
		client, err := issue.Client(c.Endpoint, provider.IssuerCredential{Bearer: string(current.Data["token"]), CA: current.Data["ca.crt"]})
		if err != nil {
			return err
		}
		if err := issue.ValidateConsumer(ctx, client, c, consumer); err != nil {
			return err
		}
		if !oldRejected && time.Now().After(oldExpiry.Add(10*time.Second)) {
			rejected := issue.ValidateConsumer(ctx, oldClient, c, consumer)
			if rejected == provider.Auth {
				oldRejected = true
			} else if rejected != nil || time.Now().After(oldExpiry.Add(2*time.Minute)) {
				return provider.Trust
			}
		}
		// A ready process with failed reflectors is not accepted CA reload evidence.
		lines := int64(30)
		logs, err := management.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &core.PodLogOptions{TailLines: &lines}).DoRaw(ctx)
		if err != nil {
			return provider.Trust
		}
		if strings.Contains(string(logs), "Unauthorized") || strings.Contains(string(logs), "forbidden") {
			return provider.Trust
		}
		if progress != nil {
			if err := progress(rotations, oldRejected, podUID); err != nil {
				return err
			}
		}
		fmt.Printf("local rotation observation: rotations=%d samePod=true restrictedAPI=true oldTokenRejected=%t\n", rotations, oldRejected)
		select {
		case <-ctx.Done():
			return provider.Transport
		case <-finish.C:
			return finishObservation(rotations, oldRejected)
		case <-ticker.C:
		}
	}
}

func finishObservation(rotations int, oldRejected bool) error {
	if rotations < 2 || !oldRejected {
		return provider.Trust
	}
	fmt.Println("local TokenFile acceptance passed: two rotations, old token rejected, same ready CA Pod")
	return nil
}
