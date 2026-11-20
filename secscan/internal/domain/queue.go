package domain

import (
	"context"
	"time"
)

// Job é uma varredura reservada (claimed) por um worker.
type Job struct {
	Result  ScanResult
	Attempt int // 1 na primeira execução; >1 quando um worker anterior morreu no meio
}

// JobQueue é a porta da fila de varreduras (semântica at-least-once, com lease).
//
//   - Enqueue: a API coloca a varredura (status "queued") na fila.
//   - Claim: um worker reserva o próximo job por um tempo (lease). Devolve (nil, nil) se a fila está vazia.
//     Jobs "running" cujo lease expirou (worker morreu) voltam a ser elegíveis, até o limite de tentativas.
//   - Extend: heartbeat; renova o lease enquanto o worker trabalha.
//   - Finish: grava o resultado final. Falha com ErrLeaseLost se outro worker assumiu o job.
//   - ReapExhausted: marca como "failed" jobs que perderam o lease e já esgotaram as tentativas.
type JobQueue interface {
	Enqueue(ctx context.Context, r ScanResult) error
	Claim(ctx context.Context, workerID string, lease time.Duration) (*Job, error)
	Extend(ctx context.Context, id, workerID string, lease time.Duration) error
	Finish(ctx context.Context, workerID string, r ScanResult) error
	ReapExhausted(ctx context.Context) (int64, error)
}
