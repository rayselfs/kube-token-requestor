package provider

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTrustBundleContainsOnlyPublicCertificates(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	canary := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("synthetic-private-material-canary")})
	rejected := map[string][]byte{
		"skipped invalid complete block": append([]byte("-----BEGIN CERTIFICATE-----\n!invalid!\n-----END CERTIFICATE-----\n"), certificate...),
		"skipped malformed block":        append([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n"), certificate...),
		"trailing private key":           append(append([]byte{}, certificate...), canary...),
		"leading private key":            append(append([]byte{}, canary...), certificate...),
		"trailing content":               append(append([]byte{}, certificate...), []byte("unexpected trailing content")...),
		"leading content":                append([]byte("unexpected leading content"), certificate...),
		"invalid certificate":            pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid DER")}),
		"PEM headers":                    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Comment": "unexpected metadata"}, Bytes: server.Certificate().Raw}),
		"empty":                          nil,
	}
	for name, input := range rejected {
		t.Run(name, func(t *testing.T) {
			client, err := HTTP(input)
			if client != nil {
				client.CloseIdleConnections()
			}
			if err != Trust {
				t.Error("non-certificate trust material was accepted")
			}
		})
	}
	for _, input := range [][]byte{certificate, append(append([]byte{}, certificate...), certificate...), append(append([]byte("\n \t"), certificate...), []byte("\n")...)} {
		client, err := HTTP(input)
		if err != nil {
			t.Fatal("valid public certificate bundle was rejected")
		}
		client.CloseIdleConnections()
	}
}
