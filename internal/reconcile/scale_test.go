package reconcile

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	jsonpatch "gopkg.in/evanphx/json-patch.v4"
	autoscaling "k8s.io/api/autoscaling/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// A typed fake does not reproduce ScaleSpec's zero omission or real REST response decoding.
func TestScaleRESTZeroFieldAndResponse(t *testing.T) {
	for _, counts := range [][2]int32{{0, 1}, {1, 0}, {0, 2}, {2, 0}} {
		from, to := counts[0], counts[1]
		t.Run(fmt.Sprint(from, "-", to), func(t *testing.T) {
			limit := int32(2)
			object := autoscaling.Scale{TypeMeta: meta.TypeMeta{APIVersion: "autoscaling/v1", Kind: "Scale"}, ObjectMeta: meta.ObjectMeta{Name: "ca", Namespace: "ns", UID: "deployment-uid", ResourceVersion: "7"}, Spec: autoscaling.ScaleSpec{Replicas: from}}
			patched := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path != "/apis/apps/v1/namespaces/ns/deployments/ca/scale" {
					t.Error("incorrect scale resource")
					w.WriteHeader(404)
					return
				}
				if r.Method == http.MethodPatch {
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
						w.WriteHeader(500)
						return
					}
					patch, err := jsonpatch.DecodePatch(body)
					if err != nil {
						t.Error(err)
						w.WriteHeader(422)
						return
					}
					before, _ := json.Marshal(object)
					after, err := patch.Apply(before)
					if err != nil {
						t.Error("patch fails on real Scale JSON shape", err)
						w.WriteHeader(422)
						return
					}
					if json.Unmarshal(after, &object) != nil || object.Spec.Replicas != to {
						t.Error("wrong desired count")
						w.WriteHeader(422)
						return
					}
					object.ResourceVersion = "8"
					patched = true
				} else if r.Method != http.MethodGet {
					t.Error("unexpected method")
					w.WriteHeader(405)
					return
				}
				_ = json.NewEncoder(w).Encode(object)
			}))
			defer server.Close()
			client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			if err := scale(context.Background(), client, config.Consumer{CADeployment: config.Deployment{Namespace: "ns", Name: "ca", UID: "deployment-uid", MaxReplicas: &limit}}, from, to); err != nil {
				t.Fatal("Scale REST operation failed", err)
			}
			if !patched {
				t.Fatal("no scale write")
			}
		})
	}
}
