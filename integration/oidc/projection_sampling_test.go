package oidc

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func TestProjectionSamplingCannotConfuseDifferentPodsWithRotation(t *testing.T) {
	b := &Broker{projected: map[string]projectionSample{}}
	// Sampling runs only after TokenReview; these are synthetic claim-observation inputs.
	token := func(uid string, expiry int64) string {
		payload := fmt.Sprintf(`{"exp":%d,"kubernetes.io":{"pod":{"uid":%q}}}`, expiry, uid)
		return "e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".synthetic"
	}
	first := token("pod-one", 1000)
	b.recordProjection(first)
	b.recordProjection(token("pod-two", 1000))
	b.recordProjection(first)
	if b.projectedSample("pod-one").Count != 1 || b.projectedSample("pod-two").Count != 1 {
		t.Fatal("two Pods or repeated exchange was mistaken for projection rotation")
	}
	b.recordProjection(token("pod-one", 1600))
	sample := b.projectedSample("pod-one")
	if sample.Count != 2 || sample.FirstExpiry != 1000 || sample.LatestExpiry != 1600 {
		t.Fatal("same-Pod renewal was not observed")
	}
	if b.BindProjectedSubject("", "new-uid") != rejected {
		t.Fatal("invalid fixture enrollment accepted")
	}
	if b.BindProjectedSubject("system:serviceaccount:fixture:controller", "new-uid") != nil || b.projectedSample("pod-one").Count != 0 {
		t.Fatal("new fixture enrollment retained predecessor observations")
	}
}
