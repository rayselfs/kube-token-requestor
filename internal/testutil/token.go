// Package testutil generates unsigned synthetic JWTs for unit tests, never real credentials.
package testutil

import (
	"encoding/base64"
	"encoding/json"
	"time"
)

func Token(subject, namespace, name, uid string, audiences []string, now time.Time, ttl int64) string {
	claims := map[string]any{"sub": subject, "aud": audiences, "iat": now.Unix(), "nbf": now.Unix(), "kubernetes.io": map[string]any{"namespace": namespace, "serviceaccount": map[string]any{"name": name, "uid": uid}}}
	if ttl > 0 {
		claims["exp"] = now.Unix() + ttl
	}
	body, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString([]byte("unsigned-unit-test"))
}
