package capacity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

type fixture struct {
	client                            kubernetes.Interface
	config                            *rest.Config
	namespace, name, kubeconfig, root string
	namespaceUID                      types.UID
	nodeIDs                           map[string]string
}

const nodeImage = "kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0"
const apiImage = "registry.k8s.io/kube-apiserver@sha256:6a7b73e718540d2c097cbcdc84c0f2cffad7a51ebccaf7f0b8cceb464715e1d9"
const etcdImage = "registry.k8s.io/etcd@sha256:70cd5d29d2efcbc4c15f2a63183fd537aae77ddbc46b3b97a8a97bc8751ec3b4"
const caDigest = "sha256:aac369dc283927a623deb1af54696efcc722ae79255aa07788422e495bab887d"

func fresh(t *testing.T, ctx context.Context) *fixture {
	t.Helper()
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal("fixture nonce failed")
	}
	f := &fixture{name: "requestor-capacity-" + hex.EncodeToString(nonce), root: t.TempDir(), nodeIDs: map[string]string{}}
	f.namespace = f.name
	f.kubeconfig = filepath.Join(f.root, "management.kubeconfig")
	configPath := filepath.Join(f.root, "kind.json")
	data, _ := json.Marshal(map[string]any{"kind": "Cluster", "apiVersion": "kind.x-k8s.io/v1alpha4", "nodes": []any{map[string]string{"role": "control-plane"}, map[string]string{"role": "worker"}}})
	if os.WriteFile(configPath, data, 0600) != nil {
		t.Fatal("fixture config write failed")
	}
	cmd := exec.CommandContext(ctx, "kind", "create", "cluster", "--name", f.name, "--config", configPath, "--kubeconfig", f.kubeconfig, "--image", nodeImage, "--wait", "3m")
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if cmd.Run() != nil {
		t.Fatal("uniquely owned capacity kind creation failed")
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		f.guardNodes(t, cleanup)
		cmd := exec.CommandContext(cleanup, "kind", "delete", "cluster", "--name", f.name)
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		if cmd.Run() != nil {
			t.Error("owned capacity cleanup failed")
		}
	})
	f.guardNodes(t, ctx)
	raw, err := clientcmd.LoadFromFile(f.kubeconfig)
	if err != nil || raw.CurrentContext != "kind-"+f.name || len(raw.AuthInfos) != 1 || len(raw.Clusters) != 1 {
		t.Fatal("fresh management kubeconfig not isolated")
	}
	for _, identity := range raw.AuthInfos {
		if identity.Exec != nil || identity.AuthProvider != nil || identity.Token != "" || identity.TokenFile != "" {
			t.Fatal("unexpected bootstrap authentication")
		}
	}
	cfg, err := clientcmd.NewDefaultClientConfig(*raw, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		t.Fatal("fixture client config failed")
	}
	endpoint, err := url.Parse(cfg.Host)
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || !net.ParseIP(endpoint.Hostname()).IsLoopback() || cfg.Insecure || len(cfg.CAData) == 0 {
		t.Fatal("fixture API must be pinned TLS over loopback")
	}
	cfg.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	cfg.Timeout = 10 * time.Second
	cfg.QPS, cfg.Burst = 30, 60
	f.config = cfg
	f.client, err = kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal("fixture management client failed")
	}
	ns, err := f.client.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: f.namespace, Labels: map[string]string{"capacity-fixture": f.name}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal("fresh namespace creation failed")
	}
	f.namespaceUID = ns.UID
	return f
}
func (f *fixture) guardNodes(t *testing.T, ctx context.Context) {
	t.Helper()
	for _, role := range []string{"control-plane", "worker"} {
		name := f.name + "-" + role
		out, err := exec.CommandContext(ctx, "docker", "inspect", "--format", `{"Id":{{json .Id}},"labels":{{json .Config.Labels}}}`, name).Output()
		if err != nil {
			t.Fatal("owned node lookup failed")
		}
		var node struct {
			ID     string `json:"Id"`
			Labels map[string]string
		}
		if json.Unmarshal(out, &node) != nil || node.ID == "" || node.Labels["io.x-k8s.kind.cluster"] != f.name || node.Labels["io.x-k8s.kind.role"] != role {
			t.Fatal("capacity node ownership rejected")
		}
		if old := f.nodeIDs[name]; old != "" && old != node.ID {
			t.Fatal("capacity node replaced; cleanup rejected")
		}
		f.nodeIDs[name] = node.ID
	}
}
func (f *fixture) guardNamespace(t *testing.T, ctx context.Context) {
	t.Helper()
	ns, err := f.client.CoreV1().Namespaces().Get(ctx, f.namespace, meta.GetOptions{})
	if err != nil || ns.UID != f.namespaceUID || ns.Labels["capacity-fixture"] != f.name {
		t.Fatal("capacity namespace identity rejected")
	}
}
func (f *fixture) forward(t *testing.T, ctx context.Context, pod string) uint16 {
	t.Helper()
	f.guardNamespace(t, ctx)
	transport, upgrader, err := spdy.RoundTripperFor(f.config)
	if err != nil {
		t.Fatal("fixture forwarding transport failed")
	}
	endpoint := f.client.CoreV1().RESTClient().Post().Resource("pods").Namespace(f.namespace).Name(pod).SubResource("portforward").URL()
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, endpoint)
	stop, ready := make(chan struct{}), make(chan struct{})
	failed := make(chan error, 1)
	forwarder, err := portforward.NewOnAddresses(dialer, []string{"127.0.0.1"}, []string{"0:6443"}, stop, ready, io.Discard, io.Discard)
	if err != nil {
		t.Fatal("fixture forwarding initialization failed")
	}
	go func() { failed <- forwarder.ForwardPorts() }()
	t.Cleanup(func() { close(stop) })
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal("fixture forwarding timed out")
	case <-failed:
		t.Fatal("fixture forwarding failed")
	}
	ports, err := forwarder.GetPorts()
	if err != nil || len(ports) != 1 || ports[0].Local == 0 {
		t.Fatal("fixture forwarding port invalid")
	}
	return ports[0].Local
}
