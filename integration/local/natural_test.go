package main

import (
	"github.com/rayselfs/kube-token-requestor/internal/config"
	"testing"
	"time"
)

func TestNaturalPolicyRejectsAcceleratedOrShortEvidence(t *testing.T) {
	l := config.Lifetime{RequestedSeconds: 86400, AcceptedMinSeconds: 79200, AcceptedMaxSeconds: 90000, RenewBeforeSeconds: 43200, StopBeforeSeconds: 1800, ClockSkewSeconds: 60}
	if !naturalPolicy(48*time.Hour, l) {
		t.Fatal("natural baseline rejected")
	}
	if naturalPolicy(47*time.Hour, l) {
		t.Fatal("short observation accepted")
	}
	accelerated := l
	accelerated.RequestedSeconds = 600
	accelerated.AcceptedMinSeconds = 590
	accelerated.AcceptedMaxSeconds = 660
	accelerated.RenewBeforeSeconds = 570
	if naturalPolicy(48*time.Hour, accelerated) {
		t.Fatal("accelerated rotations accepted as natural")
	}
	early := l
	early.RenewBeforeSeconds = 80000
	if naturalPolicy(48*time.Hour, early) {
		t.Fatal("near-immediate refresh accepted as natural")
	}
}
