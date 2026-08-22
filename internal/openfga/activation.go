package openfga

import (
	"context"
	"errors"
	"sync"
	"time"
)

var ErrNoActivation = errors.New("no active OpenFGA authorization model")
var ErrFingerprintMismatch = errors.New("active OpenFGA model fingerprint does not match configuration")

type Activation struct {
	StoreID       string
	Fingerprint   string
	ModelID       string
	SchemaVersion int
	ActivatedAt   time.Time
}

// ActivationStore is the persistence hook used to keep application metadata
// (configuration fingerprint and active immutable model ID) outside OpenFGA's
// private schema.
type ActivationStore interface {
	LoadActive(context.Context, string) (Activation, error)
	SaveActive(context.Context, Activation) error
}

type MemoryActivationStore struct {
	mu     sync.RWMutex
	values map[string]Activation
}

func NewMemoryActivationStore() *MemoryActivationStore {
	return &MemoryActivationStore{values: map[string]Activation{}}
}
func (m *MemoryActivationStore) LoadActive(_ context.Context, storeID string) (Activation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	a, ok := m.values[storeID]
	if !ok {
		return Activation{}, ErrNoActivation
	}
	return a, nil
}
func (m *MemoryActivationStore) SaveActive(_ context.Context, a Activation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.values[a.StoreID] = a
	return nil
}
