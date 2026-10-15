package publish

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	"github.com/rayselfs/kube-token-requestor/internal/issue"
	"github.com/rayselfs/kube-token-requestor/internal/testutil"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	kt "k8s.io/client-go/testing"
)

func TestSourceCASPreservesMetadataAndRejectsDrift(t *testing.T) {
	for _, mode := range []string{"valid", "same-expiry", "older", "wrong-sa", "wrong-uid", "wrong-ca", "source-replaced", "source-version-changed", "no-policy"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			now := time.Unix(2000000000, 0)
			ca := []byte("synthetic-public-ca")
			c := config.Cluster{IdentityNamespace: "identity", CASHA256: credential.Hash(ca), Audiences: []string{"api"}, ExpectedIssuer: config.Principal{Username: "system:serviceaccount:identity:issuer"}, Provider: config.Provider{Type: "SecretIssuer", Secret: &config.Ref{Namespace: "management", Name: "source", UID: "source-uid"}, ServiceAccount: &config.ServiceAccount{Name: "issuer", UID: "issuer-uid"}, Renewal: &config.Lifetime{}}}
			old := &core.Secret{ObjectMeta: meta.ObjectMeta{Namespace: "management", Name: "source", UID: "source-uid", ResourceVersion: "10", Annotations: map[string]string{"owner": "operator"}}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"ca.crt": ca, "token": []byte(testutil.Token(c.ExpectedIssuer.Username, "identity", "issuer", "issuer-uid", c.Audiences, now, 600))}}
			live := old.DeepCopy()
			if mode == "source-replaced" {
				live.UID = "different"
			}
			if mode == "source-version-changed" {
				live.ResourceVersion = "11"
			}
			client := fake.NewClientset(live)
			patches := 0
			client.PrependReactor("patch", "secrets", func(a kt.Action) (bool, runtime.Object, error) {
				patches++
				var ops []struct {
					Op    string `json:"op"`
					Path  string `json:"path"`
					Value any    `json:"value"`
				}
				if json.Unmarshal(a.(kt.PatchAction).GetPatch(), &ops) != nil || len(ops) != 3 || ops[0].Op != "test" || ops[0].Path != "/metadata/uid" || ops[0].Value != "source-uid" || ops[1].Path != "/metadata/resourceVersion" || ops[1].Value != "10" || ops[2].Op != "replace" || ops[2].Path != "/data/token" {
					t.Fatal("source CAS scope widened")
				}
				return false, nil, nil
			})
			sa, uid, ttl := "issuer", "issuer-uid", int64(3600)
			switch mode {
			case "same-expiry":
				ttl = 600
			case "older":
				ttl = 300
			case "wrong-sa":
				sa = "foreign"
			case "wrong-uid":
				uid = "foreign"
			case "no-policy":
				c.Provider.Renewal = nil
			}
			candidate := issue.Candidate{Token: testutil.Token("system:serviceaccount:identity:"+sa, "identity", sa, uid, c.Audiences, now, ttl), CA: ca, Expires: now.Add(time.Duration(ttl) * time.Second)}
			if mode == "wrong-ca" {
				candidate.CA = []byte("foreign")
			}
			err := CommitIssuer(ctx, client, c, old, candidate)
			if (err == nil) != (mode == "valid") {
				t.Fatal("source CAS accepted unsafe publication", err)
			}
			actual, _ := client.CoreV1().Secrets("management").Get(ctx, "source", meta.GetOptions{})
			if actual.Annotations["owner"] != "operator" || string(actual.Data["ca.crt"]) != string(ca) {
				t.Fatal("metadata/trust changed")
			}
			if mode == "valid" {
				if patches != 1 || string(actual.Data["token"]) != candidate.Token {
					t.Fatal("successor not published")
				}
			} else if string(actual.Data["token"]) != string(old.Data["token"]) {
				t.Fatal("failed CAS changed predecessor")
			}
			if err == nil {
				if err = CommitIssuer(ctx, client, c, actual, candidate); err == nil {
					t.Fatal("equal successor republished")
				}
			}
		})
	}
}
