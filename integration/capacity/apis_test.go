package capacity

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type child struct {
	name, endpoint string
	client         kubernetes.Interface
	bootstrap      *rest.Config
}

func secure() *core.SecurityContext {
	no, yes := false, true
	user := int64(65532)
	return &core.SecurityContext{AllowPrivilegeEscalation: &no, ReadOnlyRootFilesystem: &yes, RunAsNonRoot: &yes, RunAsUser: &user, RunAsGroup: &user, Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}, Add: []core.Capability{"NET_BIND_SERVICE"}}, SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}}
}
func resources(cpu, memory string) core.ResourceRequirements {
	return core.ResourceRequirements{Requests: core.ResourceList{core.ResourceCPU: resource.MustParse(cpu), core.ResourceMemory: resource.MustParse(memory)}, Limits: core.ResourceList{core.ResourceMemory: resource.MustParse("512Mi")}}
}
func (f *fixture) service(t *testing.T, ctx context.Context, name string, port int32) {
	t.Helper()
	f.guardNamespace(t, ctx)
	_, err := f.client.CoreV1().Services(f.namespace).Create(ctx, &core.Service{ObjectMeta: meta.ObjectMeta{Name: name}, Spec: core.ServiceSpec{Selector: map[string]string{"capacity-component": name}, Ports: []core.ServicePort{{Name: "api", Port: port}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal("capacity service creation failed")
	}
}
func (f *fixture) waitPod(t *testing.T, ctx context.Context, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	for {
		pod, err := f.client.CoreV1().Pods(f.namespace).Get(ctx, name, meta.GetOptions{})
		if err == nil && len(pod.Status.ContainerStatuses) == 1 && pod.Status.ContainerStatuses[0].Ready {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("capacity component readiness failed")
		case <-time.After(time.Second):
		}
	}
}
func (f *fixture) startDatastore(t *testing.T, ctx context.Context) {
	t.Helper()
	f.service(t, ctx, "etcd", 2379)
	group := int64(65532)
	pod := &core.Pod{ObjectMeta: meta.ObjectMeta{Name: "etcd", Labels: map[string]string{"capacity-component": "etcd"}}, Spec: core.PodSpec{AutomountServiceAccountToken: boolptr(false), Tolerations: []core.Toleration{{Key: "node-role.kubernetes.io/control-plane", Operator: core.TolerationOpExists, Effect: core.TaintEffectNoSchedule}}, SecurityContext: &core.PodSecurityContext{FSGroup: &group}, Containers: []core.Container{{Name: "etcd", Image: etcdImage, Command: []string{"/usr/local/bin/etcd"}, Args: []string{"--name=fixture", "--data-dir=/data", "--listen-client-urls=http://0.0.0.0:2379", "--advertise-client-urls=http://etcd." + f.namespace + ".svc:2379", "--listen-peer-urls=http://127.0.0.1:2380", "--initial-advertise-peer-urls=http://127.0.0.1:2380", "--initial-cluster=fixture=http://127.0.0.1:2380", "--quota-backend-bytes=67108864"}, SecurityContext: secure(), Resources: resources("100m", "128Mi"), ReadinessProbe: &core.Probe{ProbeHandler: core.ProbeHandler{TCPSocket: &core.TCPSocketAction{Port: intport(2379)}}, PeriodSeconds: 2}, VolumeMounts: []core.VolumeMount{{Name: "data", MountPath: "/data"}}}}, Volumes: []core.Volume{{Name: "data", VolumeSource: core.VolumeSource{EmptyDir: &core.EmptyDirVolumeSource{Medium: core.StorageMediumMemory, SizeLimit: quantity("256Mi")}}}}}}
	f.guardNamespace(t, ctx)
	if _, err := f.client.CoreV1().Pods(f.namespace).Create(ctx, pod, meta.CreateOptions{}); err != nil {
		t.Fatal("synthetic datastore creation failed")
	}
	f.waitPod(t, ctx, "etcd")
}
func (f *fixture) newChild(t *testing.T, ctx context.Context, name string, a *authority) *child {
	t.Helper()
	dns := name + "." + f.namespace + ".svc"
	cert, key, err := a.issue(dns, false)
	if err != nil {
		t.Fatal("child serving PKI generation failed")
	}
	adminCert, adminKey, err := a.issue("synthetic-capacity-bootstrap", true)
	if err != nil {
		t.Fatal("human-only bootstrap PKI failed")
	}
	signing, verification, err := signingKey()
	if err != nil {
		t.Fatal("child signing PKI failed")
	}
	f.guardNamespace(t, ctx)
	_, err = f.client.CoreV1().Secrets(f.namespace).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: name + "-pki"}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"ca.crt": a.public, "tls.crt": cert, "tls.key": key, "signing.key": signing, "verification.key": verification}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal("child in-API PKI creation failed")
	}
	f.service(t, ctx, name, 6443)
	endpoint := "https://" + dns + ":6443"
	f.startAPI(t, ctx, name, endpoint)
	port := f.forward(t, ctx, name)
	cfg := &rest.Config{Host: fmt.Sprintf("https://127.0.0.1:%d", port), TLSClientConfig: rest.TLSClientConfig{CAData: a.public, CertData: adminCert, KeyData: adminKey, ServerName: dns}, Timeout: 10 * time.Second, QPS: 30, Burst: 60, Proxy: func(*http.Request) (*url.URL, error) { return nil, nil }}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal("child bootstrap client failed")
	}
	for {
		version, err := client.Discovery().ServerVersion()
		if err == nil {
			if version.GitVersion != "v1.35.8" {
				t.Fatal("unexpected capacity API version")
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("actual child API bootstrap failed")
		case <-time.After(time.Second):
		}
	}
	return &child{name: name, endpoint: endpoint, client: client, bootstrap: cfg}
}
func (f *fixture) startAPI(t *testing.T, ctx context.Context, name, endpoint string) {
	t.Helper()
	group, mode := int64(65532), int32(0440)
	pod := &core.Pod{ObjectMeta: meta.ObjectMeta{Name: name, Labels: map[string]string{"capacity-component": name}}, Spec: core.PodSpec{AutomountServiceAccountToken: boolptr(false), Tolerations: []core.Toleration{{Key: "node-role.kubernetes.io/control-plane", Operator: core.TolerationOpExists, Effect: core.TaintEffectNoSchedule}}, SecurityContext: &core.PodSecurityContext{FSGroup: &group}, Containers: []core.Container{{Name: "api", Image: apiImage, Command: []string{"/usr/local/bin/kube-apiserver"}, Args: []string{"--secure-port=6443", "--advertise-address=127.0.0.1", "--tls-cert-file=/pki/tls.crt", "--tls-private-key-file=/pki/tls.key", "--client-ca-file=/pki/ca.crt", "--authorization-mode=RBAC", "--etcd-servers=http://etcd." + f.namespace + ".svc:2379", "--etcd-prefix=/capacity/" + name, "--service-cluster-ip-range=192.0.2.0/24", "--service-account-issuer=" + endpoint, "--api-audiences=" + endpoint, "--service-account-signing-key-file=/pki/signing.key", "--service-account-key-file=/pki/verification.key", "--service-account-max-token-expiration=2h", "--service-account-extend-token-expiration=false"}, SecurityContext: secure(), Resources: resources("100m", "192Mi"), ReadinessProbe: &core.Probe{ProbeHandler: core.ProbeHandler{TCPSocket: &core.TCPSocketAction{Port: intport(6443)}}, PeriodSeconds: 2}, VolumeMounts: []core.VolumeMount{{Name: "pki", MountPath: "/pki", ReadOnly: true}, {Name: "tmp", MountPath: "/tmp"}}}}, Volumes: []core.Volume{{Name: "pki", VolumeSource: core.VolumeSource{Secret: &core.SecretVolumeSource{SecretName: name + "-pki", DefaultMode: &mode}}}, {Name: "tmp", VolumeSource: core.VolumeSource{EmptyDir: &core.EmptyDirVolumeSource{Medium: core.StorageMediumMemory, SizeLimit: quantity("16Mi")}}}}}}
	f.guardNamespace(t, ctx)
	if _, err := f.client.CoreV1().Pods(f.namespace).Create(ctx, pod, meta.CreateOptions{}); err != nil {
		t.Fatal("capacity API creation failed")
	}
	f.waitPod(t, ctx, name)
}
func boolptr(value bool) *bool { return &value }

func intport(value int32) intstr.IntOrString   { return intstr.FromInt32(value) }
func quantity(value string) *resource.Quantity { q := resource.MustParse(value); return &q }
