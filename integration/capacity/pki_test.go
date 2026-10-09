package capacity

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestFixturePKISeparatesPublicTrustAndHumanBootstrap(t *testing.T) {
	a, err := newAuthority()
	if err != nil {
		t.Fatal("fixture authority failed")
	}
	if bytes.Contains(a.public, []byte("PRIVATE KEY")) {
		t.Fatal("public fixture trust contains private material")
	}
	cert, key, err := a.issue("child.fixture.svc", false)
	if err != nil {
		t.Fatal("fixture serving certificate failed")
	}
	if _, err := tls.X509KeyPair(cert, key); err != nil {
		t.Fatal("fixture key/certificate mismatch")
	}
	block, _ := pem.Decode(cert)
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal("fixture certificate invalid")
	}
	roots := x509.NewCertPool()
	roots.AddCert(a.cert)
	for _, name := range []string{"child.fixture.svc", "127.0.0.1"} {
		if _, err := parsed.Verify(x509.VerifyOptions{Roots: roots, DNSName: name}); err != nil {
			t.Fatal("fixture endpoint is not pinned by serving PKI")
		}
	}
	if _, err := parsed.Verify(x509.VerifyOptions{Roots: roots, DNSName: "another.fixture.svc"}); err == nil {
		t.Fatal("fixture certificate authenticated another endpoint")
	}
	if len(parsed.Subject.Organization) != 0 {
		t.Fatal("serving certificate acquired bootstrap privileges")
	}
	bootstrap, _, err := a.issue("human-only-bootstrap", true)
	if err != nil {
		t.Fatal("bootstrap certificate failed")
	}
	block, _ = pem.Decode(bootstrap)
	human, err := x509.ParseCertificate(block.Bytes)
	if err != nil || len(human.DNSNames) != 0 || len(human.ExtKeyUsage) != 1 || human.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatal("human bootstrap certificate was usable for serving")
	}
}
func TestFixtureSignersAreIndependent(t *testing.T) {
	_, a, err := signingKey()
	if err != nil {
		t.Fatal("signer generation failed")
	}
	_, b, err := signingKey()
	if err != nil || bytes.Equal(a, b) {
		t.Fatal("independent API signers share a key")
	}
	if bytes.Contains(a, []byte("PRIVATE KEY")) {
		t.Fatal("signer verification key exposed private material")
	}
}
