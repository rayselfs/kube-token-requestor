package status

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/rayselfs/kube-token-requestor/internal/provider"
	"github.com/rayselfs/kube-token-requestor/internal/safejson"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type Intent struct {
	Operation       string    `json:"operation"`
	Generation      string    `json:"generation"`
	DeploymentUID   string    `json:"deploymentUID"`
	Replicas        int32     `json:"replicas"`
	CandidateExpiry time.Time `json:"candidateExpiry"`
	Phase           string    `json:"phase"`
}
type Consumer struct {
	Condition       string    `json:"condition"`
	Expiry          time.Time `json:"expiry,omitempty"`
	LastSuccess     time.Time `json:"lastSuccess,omitempty"`
	Intent          *Intent   `json:"intent,omitempty"`
	StopLatched     bool      `json:"stopLatched"`
	Acknowledgement string    `json:"acknowledgement,omitempty"`
}
type Snapshot struct {
	SchemaVersion int                 `json:"schemaVersion"`
	Generation    string              `json:"generation"`
	Consumers     map[string]Consumer `json:"consumers"`
}

// Store serializes CAS updates across this process; API RV protects overlapping leaders.
type Store struct {
	Client               kubernetes.Interface
	Namespace, Name, UID string
	mu                   sync.Mutex
}

func (s *Store) Read(ctx context.Context) (Snapshot, error) {
	object, err := s.Client.CoreV1().ConfigMaps(s.Namespace).Get(ctx, s.Name, meta.GetOptions{})
	if err != nil {
		return Snapshot{}, provider.Classify(err)
	}
	if string(object.UID) != s.UID {
		return Snapshot{}, provider.Trust
	}
	return decode(object.Data["state.json"])
}
func decode(data string) (Snapshot, error) {
	if data == "" {
		return Snapshot{SchemaVersion: 1, Consumers: map[string]Consumer{}}, nil
	}
	var snapshot Snapshot
	if safejson.Decode([]byte(data), &snapshot, 1<<20) != nil || snapshot.SchemaVersion != 1 || snapshot.Consumers == nil {
		return Snapshot{}, provider.Trust
	}
	return snapshot, nil
}
func (s *Store) Update(ctx context.Context, change func(*Snapshot) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	object, err := s.Client.CoreV1().ConfigMaps(s.Namespace).Get(ctx, s.Name, meta.GetOptions{})
	if err != nil {
		return provider.Classify(err)
	}
	if string(object.UID) != s.UID {
		return provider.Trust
	}
	snapshot, err := decode(object.Data["state.json"])
	if err != nil {
		return err
	}
	if err := change(&snapshot); err != nil {
		return err
	}
	data, err := json.Marshal(snapshot)
	if err != nil || len(data) > 1<<20 {
		return provider.Trust
	}
	object.Data = map[string]string{"state.json": string(data)}
	_, err = s.Client.CoreV1().ConfigMaps(s.Namespace).Update(ctx, object, meta.UpdateOptions{})
	return provider.Classify(err)
}
