package credential

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/testutil"
)

func TestSupplementalClaims(t *testing.T) {
	now := time.Unix(2000000000, 0)
	token := testutil.Token("synthetic-subject", "ns", "consumer", "synthetic-uid", []string{"api"}, now, 3600)
	c, err := Parse(token)
	if err != nil || c.Lifetime(now, time.Minute, 3500, 3700) != nil {
		t.Fatal("valid fixture rejected")
	}
	if c.Lifetime(now.Add(3*time.Hour), time.Minute, 3500, 3700) == nil {
		t.Fatal("expired fixture accepted")
	}
	parts := strings.Split(token, ".")
	parts[0] = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	if _, err := Parse(strings.Join(parts, ".")); err == nil {
		t.Fatal("unsigned algorithm accepted")
	}
	parts[0] = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","alg":"ES256"}`))
	if _, err := Parse(strings.Join(parts, ".")); err == nil {
		t.Fatal("duplicate algorithm accepted")
	}
	if !SameSet([]string{"a", "b"}, []string{"b", "a"}) || SameSet([]string{"a", "a"}, []string{"a", "b"}) {
		t.Fatal("set mismatch")
	}
}
