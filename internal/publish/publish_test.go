package publish

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/issue"
	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/testutil"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	kt "k8s.io/client-go/testing"
)

func TestCASAndMonotonicExpiry(t *testing.T) {
	now := time.Unix(2000000000, 0)
	consumer := config.Consumer{ID: "consumer", Secret: config.Ref{Namespace: "identity", Name: "output", UID: "output-uid"}, ServiceAccount: config.ServiceAccount{Name: "ca", UID: "sa-uid"}}
	c := config.Cluster{IdentityNamespace: "identity", Audiences: []string{"api"}}
	secret := &core.Secret{ObjectMeta: meta.ObjectMeta{Namespace: "identity", Name: "output", UID: types.UID("output-uid"), ResourceVersion: "10", Annotations: map[string]string{Owner: "consumer"}}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"ca.crt": []byte("public-test-ca"), "token": {}}}
	client := fake.NewClientset(secret)
	client.PrependReactor("patch", "secrets", func(action kt.Action) (bool, runtime.Object, error) {
		patch := action.(kt.PatchAction).GetPatch()
		var operations []struct {
			Operation string `json:"op"`
			Path      string `json:"path"`
			Value     any    `json:"value"`
		}
		if json.Unmarshal(patch, &operations) != nil || len(operations) != 4 || operations[0].Value != "output-uid" || operations[1].Value != "10" || operations[2].Path != "/data/token" {
			t.Fatal("CAS preconditions missing")
		}
		return false, nil, nil
	})
	candidate := issue.Candidate{CA: secret.Data["ca.crt"], Token: testutil.Token("system:serviceaccount:identity:ca", "identity", "ca", "sa-uid", []string{"api"}, now, 3600), Expires: now.Add(time.Hour)}
	// Trust hash is mandatory even when a patch would otherwise succeed.
	if err := Commit(context.Background(), client, c, consumer, secret, candidate, "generation"); err != provider.Trust {
		t.Fatal("missing hash should prevent publication")
	}
	c.CASHA256 = credential.Hash(secret.Data["ca.crt"])
	if err := Commit(context.Background(), client, c, consumer, secret, candidate, "generation"); err != nil {
		t.Fatal("valid CAS failed")
	}
	// Equal/older candidate never issues a patch when the stored credential is already newer.
	updated, err := Read(context.Background(), client, consumer)
	if err != nil {
		t.Fatal(err)
	}
	if err := Commit(context.Background(), client, c, consumer, updated, candidate, "generation"); err != provider.Conflict {
		t.Fatal("equal expiry accepted")
	}
}

func TestOwnershipAndUID(t *testing.T) {
	consumer := config.Consumer{ID: "expected", Secret: config.Ref{Namespace: "ns", Name: "secret", UID: "expected-uid"}}
	for _, object := range []*core.Secret{
		{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "secret", UID: "wrong-uid"}, Type: core.SecretTypeOpaque},
		{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "secret", UID: "expected-uid", Annotations: map[string]string{Owner: "someone-else"}}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"ca.crt": {}, "token": {}}},
	} {
		if _, err := Read(context.Background(), fake.NewClientset(object), consumer); err != provider.Trust {
			t.Fatal("foreign output adopted")
		}
	}
}
