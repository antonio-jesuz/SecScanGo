package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/antonio-jesuz/secscan/internal/domain"
)

// Observer recebe eventos para métricas, sem acoplar a aplicação a Prometheus.
type Observer interface {
	ScanFinished(d time.Duration, r domain.ScanResult)
}

type noopObserver struct{}

func (noopObserver) ScanFinished(time.Duration, domain.ScanResult) {}

// Service é o caso de uso principal: validar alvo, rodar scanners em paralelo,
// consolidar achados e persistir o resultado.
//
// Dois modos de execução:
//   - sem fila (CLI / dev em memória): Submit executa em goroutine no próprio processo;
//   - com fila (UseQueue): Submit apenas enfileira e os workers (secscan worker) executam.
type Service struct {
	scanners []domain.Scanner
	repo     domain.ScanRepository
	queue    domain.JobQueue
	policy   TargetPolicy
	log      *slog.Logger
	timeout  time.Duration
	obs      Observer
	wg       sync.WaitGroup
}

func NewService(scanners []domain.Scanner, repo domain.ScanRepository, policy TargetPolicy,
	log *slog.Logger, timeout time.Duration, obs Observer) *Service {
	if obs == nil {
		obs = noopObserver{}
	}
	if log == nil {
		log = slog.Default()
	}
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	return &Service{scanners: scanners, repo: repo, policy: policy, log: log, timeout: timeout, obs: obs}
}

// UseQueue ativa o modo fila: Submit passa a apenas enfileirar.
func (s *Service) UseQueue(q domain.JobQueue) { s.queue = q }

// Run executa de forma síncrona (usado pela CLI).
func (s *Service) Run(ctx context.Context, t domain.Target) (domain.ScanResult, error) {
	res, err := s.newResult(ctx, t, domain.StatusRunning)
	if err != nil {
		return domain.ScanResult{}, err
	}
	if err := s.repo.Save(ctx, res); err != nil {
		return domain.ScanResult{}, fmt.Errorf("salvar varredura: %w", err)
	}
	return s.execute(ctx, res), nil
}

// Submit devolve imediatamente (usado pela API). Com fila, enfileira; sem fila, roda em background.
func (s *Service) Submit(ctx context.Context, t domain.Target) (domain.ScanResult, error) {
	if s.queue != nil {
		res, err := s.newResult(ctx, t, domain.StatusQueued)
		if err != nil {
			return domain.ScanResult{}, err
		}
		if err := s.queue.Enqueue(ctx, res); err != nil {
			return domain.ScanResult{}, fmt.Errorf("enfileirar varredura: %w", err)
		}
		s.log.Info("varredura enfileirada", "scan_id", res.ID, "target", res.Target.Host)
		return res, nil
	}

	res, err := s.newResult(ctx, t, domain.StatusRunning)
	if err != nil {
		return domain.ScanResult{}, err
	}
	if err := s.repo.Save(ctx, res); err != nil {
		return domain.ScanResult{}, fmt.Errorf("salvar varredura: %w", err)
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.execute(context.Background(), res)
	}()
	return res, nil
}

// Wait bloqueia até as varreduras em background terminarem (graceful shutdown).
func (s *Service) Wait() { s.wg.Wait() }

func (s *Service) newResult(ctx context.Context, t domain.Target, status domain.Status) (domain.ScanResult, error) {
	t.Host = strings.TrimSpace(t.Host)
	if err := s.policy.Validate(ctx, t.Host); err != nil {
		return domain.ScanResult{}, err
	}
	id, err := newID()
	if err != nil {
		return domain.ScanResult{}, fmt.Errorf("gerar id: %w", err)
	}
	return domain.ScanResult{ID: id, Target: t, Status: status, StartedAt: time.Now().UTC()}, nil
}

// execute = scan + persistência + métricas (modo sem fila).
func (s *Service) execute(ctx context.Context, res domain.ScanResult) domain.ScanResult {
	start := time.Now()
	res = s.scan(ctx, res)
	if err := s.repo.Save(context.Background(), res); err != nil {
		s.log.Error("falha ao salvar resultado", "scan_id", res.ID, "err", err)
	}
	s.report(res, time.Since(start))
	return res
}

func (s *Service) report(res domain.ScanResult, d time.Duration) {
	s.obs.ScanFinished(d, res)
	s.log.Info("varredura finalizada", "scan_id", res.ID, "target", res.Target.Host,
		"status", res.Status, "findings", len(res.Findings), "duration", d.String())
}

// scan roda todos os scanners em paralelo e consolida. Não persiste nada:
// quem chama decide como gravar (repo.Save ou queue.Finish).
func (s *Service) scan(ctx context.Context, res domain.ScanResult) domain.ScanResult {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	type outcome struct {
		name     string
		findings []domain.Finding
		err      error
	}
	ch := make(chan outcome, len(s.scanners))
	for _, sc := range s.scanners {
		go func(sc domain.Scanner) {
			defer func() {
				if r := recover(); r != nil {
					ch <- outcome{name: sc.Name(), err: fmt.Errorf("panic: %v", r)}
				}
			}()
			f, err := sc.Scan(ctx, res.Target)
			ch <- outcome{name: sc.Name(), findings: f, err: err}
		}(sc)
	}

	res.Findings = nil
	res.Errors = nil
	failed := 0
	for range s.scanners {
		o := <-ch
		res.Findings = append(res.Findings, o.findings...)
		if o.err != nil {
			failed++
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", o.name, o.err))
		}
	}

	res.Status = domain.StatusCompleted
	if failed > 0 && failed == len(s.scanners) {
		res.Status = domain.StatusFailed
	}
	finished := time.Now().UTC()
	res.FinishedAt = &finished
	sort.SliceStable(res.Findings, func(i, j int) bool {
		if res.Findings[i].Severity != res.Findings[j].Severity {
			return res.Findings[i].Severity > res.Findings[j].Severity
		}
		return res.Findings[i].ID < res.Findings[j].ID
	})
	return res
}

func newID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
