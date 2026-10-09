package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/rayselfs/kube-token-requestor/internal/config"
)

func TestSubjectInputRevisionTracksRotationWithoutRetainingToken(t *testing.T) {
	subject := []byte("synthetic-first-subject-canary")
	reads := 0
	p := OAuthTokenExchange{Subject: func(string) ([]byte, error) { reads++; return subject, nil }}
	c := config.Cluster{Provider: config.Provider{Type: "OAuthTokenExchange", SubjectTokenVolume: "broker"}}
	first, err := p.InputRevision(context.Background(), c)
	if err != nil || len(first) != 64 || strings.Contains(first, "canary") {
		t.Fatal("input revision exposed credential material or failed")
	}
	same, err := p.InputRevision(context.Background(), c)
	if err != nil || same != first || reads != 2 {
		t.Fatal("subject revision was cached or unstable")
	}
	subject = []byte("synthetic-second-subject-canary")
	second, err := p.InputRevision(context.Background(), c)
	if err != nil || second == first {
		t.Fatal("subject revision did not change on rotation")
	}
	subject = make([]byte, 32769)
	if _, err := p.InputRevision(context.Background(), c); err != Auth {
		t.Fatal("oversized subject accepted")
	}
}
