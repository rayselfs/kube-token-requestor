package capacity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"
)

// Private fixture PKI stays in memory or the uniquely owned synthetic API's Secrets.
// It is never written to the source tree, command arguments, logs or evidence.
type authority struct {
	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
	public []byte
}

func serial() (*big.Int, error) { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)) }
func newAuthority() (*authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	number, err := serial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	c := &x509.Certificate{SerialNumber: number, Subject: pkix.Name{CommonName: "synthetic capacity CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &authority{parsed, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}
func (a *authority) issue(name string, client bool) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	number, err := serial()
	if err != nil {
		return nil, nil, err
	}
	c := &x509.Certificate{SerialNumber: number, Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: a.cert.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{name}}
	if !client {
		c.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	if client {
		c.DNSNames = nil
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		c.Subject.Organization = []string{"system:masters"}
	} // Human fixture bootstrap only; never used by the controller.
	der, err := x509.CreateCertificate(rand.Reader, c, a.cert, &key.PublicKey, a.key)
	if err != nil {
		return nil, nil, err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), nil
}
func signingKey() ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}), nil
}
