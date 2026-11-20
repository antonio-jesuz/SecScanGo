package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/antonio-jesuz/secscan/internal/domain"
)

// Testes de integração: exigem um PostgreSQL.
//   SECSCAN_TEST_DATABASE_URL='postgres://secscan:secscan-dev@localhost:5432/secscan?sslmode=disable' go test ./internal/infrastructure/storage/...
// Cada teste cria um schema próprio (search_path) e o remove no final: não toca nos seus dados reais.
func isolatedRepo(t *testing.T) *PostgresRepository {
	t.Helper()
	url := os.Getenv("SECSCAN_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("SECSCAN_TEST_DATABASE_URL não definida; pulando teste de integração")
	}
	schema := fmt.Sprintf("qtest_%d", time.Now().UnixNano())
	admin, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec("DROP SCHEMA " + schema + " CASCADE")
		_ = admin.Close()
	})

	sep := "?"
	if strings.Contains(url, "?") {
		sep = "&"
	}
	repo, err := OpenPostgres(context.Background(), url+sep+"search_path="+schema)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	return repo
}

func TestPostgresRoundTrip(t *testing.T) {
	repo := isolatedRepo(t)
	ctx := context.Background()

	fin := time.Now().UTC().Truncate(time.Millisecond)
	in := domain.ScanResult{
		ID: "rt", Target: domain.Target{Host: "example.test"}, Status: domain.StatusCompleted,
		StartedAt: fin.Add(-time.Second), FinishedAt: &fin,
		Findings: []domain.Finding{{ID: "X-1", Severity: domain.SeverityHigh, Title: "t"}},
	}
	if err := repo.Save(ctx, in); err != nil {
		t.Fatal(err)
	}
	got, err := repo.Get(ctx, in.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != in.ID || len(got.Findings) != 1 || got.Findings[0].Severity != domain.SeverityHigh {
		t.Errorf("round-trip divergente: %+v", got)
	}
	if _, err := repo.Get(ctx, "nao-existe"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("esperava ErrNotFound, veio %v", err)
	}
}

func enqueue(t *testing.T, repo *PostgresRepository, id string) {
	t.Helper()
	err := repo.Enqueue(context.Background(), domain.ScanResult{
		ID: id, Target: domain.Target{Host: "example.test"}, Status: domain.StatusQueued, StartedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestQueueClaimIsExclusiveAndFinishRequiresLease(t *testing.T) {
	repo := isolatedRepo(t)
	ctx := context.Background()
	enqueue(t, repo, "q1")

	j1, err := repo.Claim(ctx, "w1", time.Hour)
	if err != nil || j1 == nil || j1.Attempt != 1 || j1.Result.Status != domain.StatusRunning {
		t.Fatalf("claim w1 = %+v, %v", j1, err)
	}
	if j2, err := repo.Claim(ctx, "w2", time.Hour); err != nil || j2 != nil {
		t.Fatalf("w2 não deveria reservar o mesmo job: %+v, %v", j2, err)
	}
	if err := repo.Extend(ctx, "q1", "w2", time.Hour); !errors.Is(err, domain.ErrLeaseLost) {
		t.Errorf("Extend por quem não é dono deveria falhar, err = %v", err)
	}

	fin := time.Now().UTC()
	done := j1.Result
	done.Status, done.FinishedAt = domain.StatusCompleted, &fin
	if err := repo.Finish(ctx, "w2", done); !errors.Is(err, domain.ErrLeaseLost) {
		t.Errorf("Finish por quem não é dono deveria falhar, err = %v", err)
	}
	if err := repo.Finish(ctx, "w1", done); err != nil {
		t.Fatal(err)
	}
	got, _ := repo.Get(ctx, "q1")
	if got.Status != domain.StatusCompleted {
		t.Errorf("status = %s", got.Status)
	}
}

func TestQueueRetriesAfterLeaseExpiryAndExhausts(t *testing.T) {
	repo := isolatedRepo(t)
	ctx := context.Background()
	enqueue(t, repo, "q2")

	// worker w1 "morre": lease de 30ms expira sem Finish
	if j, err := repo.Claim(ctx, "w1", 30*time.Millisecond); err != nil || j == nil {
		t.Fatalf("claim 1: %+v %v", j, err)
	}
	time.Sleep(80 * time.Millisecond)
	j, err := repo.Claim(ctx, "w2", 30*time.Millisecond)
	if err != nil || j == nil || j.Attempt != 2 {
		t.Fatalf("job deveria ser reexecutado na tentativa 2: %+v %v", j, err)
	}
	if err := repo.Finish(ctx, "w1", j.Result); !errors.Is(err, domain.ErrLeaseLost) {
		t.Errorf("w1 (zumbi) não pode gravar resultado, err = %v", err)
	}

	// terceira tentativa também expira -> esgotado
	time.Sleep(80 * time.Millisecond)
	if j3, _ := repo.Claim(ctx, "w3", 30*time.Millisecond); j3 == nil || j3.Attempt != 3 {
		t.Fatalf("tentativa 3 esperada: %+v", j3)
	}
	time.Sleep(80 * time.Millisecond)
	if j4, _ := repo.Claim(ctx, "w4", time.Second); j4 != nil {
		t.Fatalf("não deveria haver 4ª tentativa: %+v", j4)
	}
	n, err := repo.ReapExhausted(ctx)
	if err != nil || n != 1 {
		t.Fatalf("ReapExhausted = %d, %v", n, err)
	}
	got, _ := repo.Get(ctx, "q2")
	if got.Status != domain.StatusFailed || len(got.Errors) == 0 {
		t.Errorf("esperava failed com erro: %+v", got)
	}
}
