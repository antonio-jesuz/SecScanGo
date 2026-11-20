// Package storage contém adaptadores de persistência.
package storage

import (
	"context"
	"sort"
	"sync"

	"github.com/antonio-jesuz/secscan/internal/domain"
)

// MemoryRepository é um repositório thread-safe em memória.
// Para produção, implemente domain.ScanRepository com PostgreSQL (veja docs/ARCHITECTURE.md).
type MemoryRepository struct {
	mu   sync.RWMutex
	data map[string]domain.ScanResult
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{data: make(map[string]domain.ScanResult)}
}

func (m *MemoryRepository) Save(_ context.Context, r domain.ScanResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[r.ID] = r
	return nil
}

func (m *MemoryRepository) Get(_ context.Context, id string) (domain.ScanResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.data[id]
	if !ok {
		return domain.ScanResult{}, domain.ErrNotFound
	}
	return r, nil
}

func (m *MemoryRepository) List(_ context.Context) ([]domain.ScanResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.ScanResult, 0, len(m.data))
	for _, r := range m.data {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	return out, nil
}
