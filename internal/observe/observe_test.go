package observe

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/status"
)

func TestStandbyAndSanitizedMetrics(t *testing.T) {
	m := &Metrics{}
	m.Record("cluster", "consumer", "sensitive-canary", time.Unix(2000000000, 0))
	m.State("cluster", "consumer", status.Consumer{Condition: "SafetyStopped"})
	r := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, r)
	if strings.Contains(w.Body.String(), "consumer=\"") {
		t.Fatal("standby exports target state")
	}
	m.Leader.Store(true)
	w = httptest.NewRecorder()
	m.Handler().ServeHTTP(w, r)
	if strings.Contains(w.Body.String(), "canary") || !strings.Contains(w.Body.String(), "SafetyStopped") {
		t.Fatal("invalid target metrics")
	}
	m.Reset()
	w = httptest.NewRecorder()
	m.Handler().ServeHTTP(w, r)
	if strings.Contains(w.Body.String(), "consumer=\"") {
		t.Fatal("offboarded series retained")
	}
}

func TestLeadershipChangesAreCounter(t *testing.T) {
	m := &Metrics{}
	m.Changes.Add(2)
	families, err := m.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() == "kube_token_requestor_leadership_changes_total" {
			if family.GetType().String() != "COUNTER" || family.Metric[0].GetCounter().GetValue() != 2 {
				t.Fatal("leadership changes are not a monotonic counter")
			}
			return
		}
	}
	t.Fatal("missing leadership counter")
}

func TestLivenessDetectsStalledControlLoop(t *testing.T) {
	m := &Metrics{}
	handler := m.Handler()
	m.Progress.Store(time.Now().Add(-3 * time.Minute).Unix())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/livez", nil))
	if w.Code != 503 {
		t.Fatal("stalled process reports alive")
	}
	m.Progress.Store(time.Now().Unix())
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/livez", nil))
	if w.Code != 200 {
		t.Fatal("healthy process reports dead")
	}
}
