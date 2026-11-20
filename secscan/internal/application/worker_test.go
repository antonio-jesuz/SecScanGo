package application

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/antonio-jesuz/secscan/internal/domain"
	"github.com/antonio-jesuz/secscan/internal/infrastructure/storage"
)

type fakeQueue struct {
	mu       sync.Mutex
	jobs     []domain.Job
	finished chan domain.ScanResult
}

func newFakeQueue(jobs ...domain.Job) *fakeQueue {
	return &fakeQueue{jobs: jobs, finished: make(chan domain.ScanResult, 10)}
}

func (q *fakeQueue) Enqueue(context.Context, domain.ScanResult) error { return nil }
func (q *fakeQueue) Claim(context.Context, string, time.Duration) (*domain.Job, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.jobs) == 0 {
		return nil, nil
	}
	j := q.jobs[0]
	q.jobs = q.jobs[1:]
	return &j, nil
}
func (q *fakeQueue) Extend(context.Context, string, string, time.Duration) error { return nil }
func (q *fakeQueue) Finish(_ context.Context, _ string, r domain.ScanResult) error {
	q.finished <- r
	return nil
}
func (q *fakeQueue) ReapExhausted(context.Context) (int64, error) { return 0, nil }

func runWorkerUntilFinished(t *testing.T, w *Worker, q *fakeQueue) domain.ScanResult {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	select {
	case r := <-q.finished:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("worker não finalizou o job a tempo")
		return domain.ScanResult{}
	}
}

func TestWorkerProcessesJob(t *testing.T) {
	svc := NewService([]domain.Scanner{
		fakeScanner{name: "a", f: []domain.Finding{{ID: "H", Severity: domain.SeverityHigh}}},
	}, storage.NewMemoryRepository(), TargetPolicy{AllowPrivate: true}, nil, 5*time.Second, nil)
	q := newFakeQueue(domain.Job{
		Attempt: 1,
		Result:  domain.ScanResult{ID: "j1", Target: domain.Target{Host: "127.0.0.1"}, Status: domain.StatusRunning},
	})
	w := NewWorker(svc, q, WorkerConfig{ID: "w1", Concurrency: 1, Lease: time.Second, Poll: 10 * time.Millisecond}, nil)

	got := runWorkerUntilFinished(t, w, q)
	if got.ID != "j1" || got.Status != domain.StatusCompleted || len(got.Findings) != 1 {
		t.Errorf("resultado inesperado: %+v", got)
	}
}

func TestWorkerRevalidatesPolicy(t *testing.T) {
	// Política estrita: o alvo (loopback) deve ser rejeitado pelo worker mesmo que a API o tenha aceitado antes.
	svc := NewService([]domain.Scanner{fakeScanner{name: "a"}}, storage.NewMemoryRepository(),
		TargetPolicy{}, nil, 5*time.Second, nil)
	q := newFakeQueue(domain.Job{
		Attempt: 1,
		Result:  domain.ScanResult{ID: "j2", Target: domain.Target{Host: "127.0.0.1"}, Status: domain.StatusRunning},
	})
	w := NewWorker(svc, q, WorkerConfig{ID: "w1", Concurrency: 1, Poll: 10 * time.Millisecond}, nil)

	got := runWorkerUntilFinished(t, w, q)
	if got.Status != domain.StatusFailed || len(got.Errors) == 0 {
		t.Errorf("esperava failed com erro de política: %+v", got)
	}
}

func TestSubmitWithQueueOnlyEnqueues(t *testing.T) {
	q := newFakeQueue()
	svc := NewService(nil, storage.NewMemoryRepository(), TargetPolicy{AllowPrivate: true}, nil, time.Second, nil)
	svc.UseQueue(q)
	res, err := svc.Submit(context.Background(), domain.Target{Host: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != domain.StatusQueued {
		t.Errorf("status = %s, quer queued", res.Status)
	}
}
