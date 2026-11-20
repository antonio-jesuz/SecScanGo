package application

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/antonio-jesuz/secscan/internal/domain"
)

// WorkerConfig parametriza o consumo da fila.
type WorkerConfig struct {
	ID          string        // identifica o worker nos leases (hostname-pid)
	Concurrency int           // varreduras simultâneas neste processo
	Lease       time.Duration // validade do lease; renovado por heartbeat a cada Lease/3
	Poll        time.Duration // intervalo de consulta quando a fila está vazia
}

// Worker consome a fila de varreduras. Pode haver N workers (processos/containers) em paralelo:
// a fila garante que cada job é reservado por um único worker por vez.
type Worker struct {
	svc   *Service
	queue domain.JobQueue
	cfg   WorkerConfig
	log   *slog.Logger
}

func NewWorker(svc *Service, q domain.JobQueue, cfg WorkerConfig, log *slog.Logger) *Worker {
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 1
	}
	if cfg.Lease <= 0 {
		cfg.Lease = 30 * time.Second
	}
	if cfg.Poll <= 0 {
		cfg.Poll = 2 * time.Second
	}
	if log == nil {
		log = slog.Default()
	}
	return &Worker{svc: svc, queue: q, cfg: cfg, log: log}
}

// Run bloqueia até ctx ser cancelado e os jobs em andamento terminarem.
// Ao cancelar, o worker PARA de reservar jobs novos mas deixa os atuais concluírem.
func (w *Worker) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for i := 0; i < w.cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.loop(ctx)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		w.reaper(ctx)
	}()
	wg.Wait()
}

func (w *Worker) loop(ctx context.Context) {
	for ctx.Err() == nil {
		job, err := w.queue.Claim(ctx, w.cfg.ID, w.cfg.Lease)
		if err != nil {
			if ctx.Err() == nil {
				w.log.Error("falha ao reservar job", "err", err)
			}
			w.sleep(ctx)
			continue
		}
		if job == nil {
			w.sleep(ctx)
			continue
		}
		w.process(job)
	}
}

func (w *Worker) sleep(ctx context.Context) {
	select {
	case <-time.After(w.cfg.Poll):
	case <-ctx.Done():
	}
}

// reaper marca como "failed" jobs que esgotaram as tentativas (workers que morreram repetidamente).
func (w *Worker) reaper(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := w.queue.ReapExhausted(ctx)
			if err != nil {
				if ctx.Err() == nil {
					w.log.Error("falha no reaper", "err", err)
				}
				continue
			}
			if n > 0 {
				w.log.Warn("jobs marcados como failed por esgotar tentativas", "count", n)
			}
		}
	}
}

func (w *Worker) process(job *domain.Job) {
	start := time.Now()
	res := job.Result
	log := w.log.With("scan_id", res.ID, "attempt", job.Attempt, "worker", w.cfg.ID)
	log.Info("job reservado", "target", res.Target.Host)

	// O scan roda num contexto próprio: SIGTERM não o aborta (graceful); só a perda do lease.
	scanCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Defesa em profundidade: reavalia a política (o DNS pode ter mudado desde o enfileiramento).
	if err := w.svc.policy.Validate(scanCtx, res.Target.Host); err != nil {
		finished := time.Now().UTC()
		res.Status = domain.StatusFailed
		res.FinishedAt = &finished
		res.Errors = append(res.Errors, "política: "+err.Error())
		w.finish(res, start, log)
		return
	}

	hbDone := make(chan struct{})
	go func() {
		defer close(hbDone)
		t := time.NewTicker(w.cfg.Lease / 3)
		defer t.Stop()
		for {
			select {
			case <-scanCtx.Done():
				return
			case <-t.C:
				err := w.queue.Extend(scanCtx, res.ID, w.cfg.ID, w.cfg.Lease)
				if errors.Is(err, domain.ErrLeaseLost) {
					log.Warn("lease perdido durante a varredura; abortando")
					cancel()
					return
				}
				if err != nil && scanCtx.Err() == nil {
					log.Error("falha no heartbeat", "err", err)
				}
			}
		}
	}()

	res = w.svc.scan(scanCtx, res)
	cancel()
	<-hbDone
	w.finish(res, start, log)
}

func (w *Worker) finish(res domain.ScanResult, start time.Time, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := w.queue.Finish(ctx, w.cfg.ID, res); err != nil {
		if errors.Is(err, domain.ErrLeaseLost) {
			log.Warn("resultado descartado: outro worker assumiu o job")
			return
		}
		log.Error("falha ao gravar resultado", "err", err)
		return
	}
	w.svc.report(res, time.Since(start))
}
