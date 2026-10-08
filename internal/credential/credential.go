// Package credential performs supplemental checks; only an authenticated API verifies tokens.
package credential

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/safejson"
)

var ErrInvalid = errors.New("credential rejected")

type Audience []string

func (a *Audience) UnmarshalJSON(data []byte) error {
	var text string
	if json.Unmarshal(data, &text) == nil {
		*a = []string{text}
		return nil
	}
	var values []string
	if json.Unmarshal(data, &values) != nil || values == nil {
		return ErrInvalid
	}
	*a = values
	return nil
}

type Claims struct {
	Subject    string   `json:"sub"`
	Audience   Audience `json:"aud"`
	Expires    int64    `json:"exp"`
	Issued     int64    `json:"iat"`
	NotBefore  int64    `json:"nbf"`
	Kubernetes struct {
		Namespace      string `json:"namespace"`
		ServiceAccount struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"serviceaccount"`
	} `json:"kubernetes.io"`
}

func Parse(token string) (Claims, error) {
	var c Claims
	if len(token) == 0 || len(token) > 32768 || strings.ContainsAny(token, " \t\r\n\x00") {
		return c, ErrInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[2] == "" {
		return c, ErrInvalid
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return c, ErrInvalid
	}
	var h struct {
		Algorithm string `json:"alg"`
	}
	if safejson.Decode(header, &h, 4096) != nil || (h.Algorithm != "RS256" && h.Algorithm != "ES256" && h.Algorithm != "EdDSA") {
		return c, ErrInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c, ErrInvalid
	}
	if safejson.Decode(payload, &c, 24576) != nil || c.Subject == "" {
		return c, ErrInvalid
	}
	return c, nil
}

func (c Claims) Lifetime(now time.Time, skew time.Duration, min, max int64) error {
	remaining := c.Expires - now.Unix()
	if c.Expires <= 0 || c.Issued <= 0 || c.Issued > now.Add(skew).Unix() || c.NotBefore > now.Add(skew).Unix() ||
		remaining < min-int64(skew.Seconds()) || remaining > max+int64(skew.Seconds()) || c.Expires-c.Issued < min || c.Expires-c.Issued > max {
		return ErrInvalid
	}
	return nil
}

func SameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]bool{}
	for _, x := range a {
		if seen[x] {
			return false
		}
		seen[x] = true
	}
	for _, x := range b {
		if !seen[x] {
			return false
		}
		delete(seen, x)
	}
	return len(seen) == 0
}

func Hash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
