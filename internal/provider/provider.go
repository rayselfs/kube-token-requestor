package provider

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/config"
	"github.com/rayselfs/kube-token-requestor/internal/credential"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type Failure string

type Retry struct{ After time.Duration }

func (r *Retry) Error() string { return string(Transport) }

const (
	Transport Failure = "Transport"
	Trust     Failure = "TrustRejected"
	Auth      Failure = "BootstrapRequired"
	Conflict  Failure = "Conflict"
)

func (f Failure) Error() string { return string(f) }

func Classify(err error) error {
	if err == nil {
		return nil
	}
	var failure Failure
	if errors.As(err, &failure) {
		return failure
	}
	var retry *Retry
	if errors.As(err, &retry) {
		return retry
	}
	if seconds, ok := apierrors.SuggestsClientDelay(err); ok && seconds > 0 {
		return &Retry{After: min(time.Duration(seconds)*time.Second, 5*time.Minute)}
	}
	if apierrors.IsUnauthorized(err) || apierrors.IsForbidden(err) {
		return Auth
	}
	if apierrors.IsConflict(err) || apierrors.IsInvalid(err) {
		return Conflict
	}
	if apierrors.IsNotFound(err) {
		return Trust
	}
	return Transport
}

type IssuerCredential struct {
	Bearer      string
	CA          []byte
	Expires     time.Time
	RotationDue time.Time
}
type IssuerProvider interface {
	Acquire(context.Context, config.Cluster) (IssuerCredential, error)
	// InputRevision is a private opaque marker for inputs outside API Secret metadata.
	InputRevision(context.Context, config.Cluster) (string, error)
}

func ReadSecret(ctx context.Context, client kubernetes.Interface, ref config.Ref, keys ...string) (*core.Secret, error) {
	s, err := client.CoreV1().Secrets(ref.Namespace).Get(ctx, ref.Name, meta.GetOptions{})
	if err != nil {
		return nil, Classify(err)
	}
	if string(s.UID) != ref.UID || s.Type != core.SecretTypeOpaque || (s.Immutable != nil && *s.Immutable) || len(s.Data) != len(keys) {
		return nil, Trust
	}
	for _, key := range keys {
		if len(s.Data[key]) == 0 {
			return nil, Trust
		}
	}
	return s, nil
}

func HTTP(ca []byte) (*http.Client, error) {
	pool := x509.NewCertPool()
	remaining := bytes.TrimSpace(ca)
	if len(remaining) == 0 {
		return nil, Trust
	}
	for len(remaining) > 0 {
		// PEM decoding otherwise skips unrelated material that would be copied
		// unchanged into consumer trust bundles.
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, Trust
		}
		end := bytes.Index(remaining, []byte("-----END CERTIFICATE-----"))
		if end < 0 || bytes.Contains(remaining[len("-----BEGIN CERTIFICATE-----"):end], []byte("-----BEGIN ")) {
			return nil, Trust
		}
		end += len("-----END CERTIFICATE-----")
		block, rest := pem.Decode(remaining[:end])
		if block == nil || len(bytes.TrimSpace(rest)) != 0 || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, Trust
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, Trust
		}
		pool.AddCert(certificate)
		remaining = bytes.TrimSpace(remaining[end:])
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, Proxy: nil, MaxIdleConns: 8, IdleConnTimeout: 30 * time.Second}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return Trust }}, nil
}

type SecretIssuer struct {
	Management kubernetes.Interface
	Now        func() time.Time
}

func (p SecretIssuer) InputRevision(ctx context.Context, _ config.Cluster) (string, error) {
	return "", Classify(ctx.Err())
}

func (p SecretIssuer) Acquire(ctx context.Context, c config.Cluster) (IssuerCredential, error) {
	var result IssuerCredential
	if c.Provider.Type != "SecretIssuer" || c.Provider.Secret == nil || c.Provider.LongLived == nil {
		return result, Trust
	}
	s, err := ReadSecret(ctx, p.Management, *c.Provider.Secret, "ca.crt", "token")
	if err != nil {
		return result, err
	}
	if credential.Hash(s.Data["ca.crt"]) != c.CASHA256 {
		return result, Trust
	}
	if _, err := HTTP(s.Data["ca.crt"]); err != nil {
		return result, err
	}
	claims, err := credential.Parse(string(s.Data["token"]))
	if err != nil {
		return result, Auth
	}
	if claims.Subject != c.ExpectedIssuer.Username {
		return result, Auth
	}
	if *c.Provider.LongLived {
		rotated, err := time.Parse(time.RFC3339, s.Annotations["token-requestor.io/rotated-at"])
		if err != nil || rotated.After(p.Now().Add(time.Minute)) {
			return result, Trust
		}
		result.RotationDue = rotated.Add(time.Duration(c.Provider.RotationPeriodSeconds) * time.Second)
		if !result.RotationDue.After(p.Now()) {
			return result, Auth
		}
		if claims.Expires != 0 {
			return result, Auth
		}
	} else {
		now := p.Now()
		if claims.Expires <= now.Add(time.Duration(c.Lifetime.StopBeforeSeconds+c.Lifetime.ClockSkewSeconds)*time.Second).Unix() {
			return result, Auth
		}
		result.Expires = time.Unix(claims.Expires, 0)
	}
	result.Bearer, result.CA = string(s.Data["token"]), append([]byte(nil), s.Data["ca.crt"]...)
	return result, nil
}
