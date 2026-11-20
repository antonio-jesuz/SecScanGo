package storage

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // driver "pgx" para database/sql

	"github.com/antonio-jesuz/secscan/internal/domain"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// PostgresRepository implementa domain.ScanRepository. O resultado completo fica em JSONB;
// colunas escalares (host, status, datas) existem para filtros e índices.
type PostgresRepository struct {
	db *sql.DB
}

// OpenPostgres conecta (com retry de até 30s, pois o banco pode estar subindo no compose)
// e aplica as migrations. API e workers chamam isto ao mesmo tempo; um advisory lock serializa as migrations.
func OpenPostgres(ctx context.Context, url string) (*PostgresRepository, error) {
	db, err := sql.Open("pgx", url)
	if err != nil {
		return nil, fmt.Errorf("abrir conexão: %w", err)
	}
	db.SetMaxOpenConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)

	deadline := time.Now().Add(30 * time.Second)
	for {
		pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		err = db.PingContext(pctx)
		cancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			_ = db.Close()
			return nil, fmt.Errorf("postgres indisponível: %w", err)
		}
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
		}
	}

	r := &PostgresRepository{db: db}
	if err := r.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrations: %w", err)
	}
	return r, nil
}

func (p *PostgresRepository) Close() error { return p.db.Close() }

const migrationLockID = 727274 // chave arbitrária do advisory lock

func (p *PostgresRepository) migrate(ctx context.Context) error {
	// Vários processos (API + N workers) sobem juntos: o lock evita corrida no CREATE/ALTER.
	conn, err := p.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrationLockID); err != nil {
		return fmt.Errorf("advisory lock: %w", err)
	}
	defer func() { _, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, migrationLockID) }()

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, n := range names {
		sqlText, err := migrationsFS.ReadFile("migrations/" + n)
		if err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, string(sqlText)); err != nil {
			return fmt.Errorf("%s: %w", n, err)
		}
	}
	return nil
}

func (p *PostgresRepository) Save(ctx context.Context, r domain.ScanResult) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = p.db.ExecContext(ctx, `
		INSERT INTO scans (id, host, status, started_at, finished_at, data)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb)
		ON CONFLICT (id) DO UPDATE
		   SET status = EXCLUDED.status,
		       finished_at = EXCLUDED.finished_at,
		       data = EXCLUDED.data`,
		r.ID, r.Target.Host, string(r.Status), r.StartedAt, r.FinishedAt, string(data))
	return err
}

func (p *PostgresRepository) Get(ctx context.Context, id string) (domain.ScanResult, error) {
	var raw []byte
	err := p.db.QueryRowContext(ctx, `SELECT data FROM scans WHERE id = $1`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ScanResult{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.ScanResult{}, err
	}
	var res domain.ScanResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return domain.ScanResult{}, fmt.Errorf("decodificar resultado %s: %w", id, err)
	}
	return res, nil
}

func (p *PostgresRepository) List(ctx context.Context) ([]domain.ScanResult, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT data FROM scans ORDER BY started_at DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.ScanResult{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var res domain.ScanResult
		if err := json.Unmarshal(raw, &res); err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, rows.Err()
}

// ---------- JobQueue (fila sobre PostgreSQL: FOR UPDATE SKIP LOCKED) ----------

var _ domain.JobQueue = (*PostgresRepository)(nil)

func (p *PostgresRepository) Enqueue(ctx context.Context, r domain.ScanResult) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = p.db.ExecContext(ctx, `
		INSERT INTO scans (id, host, status, started_at, data)
		VALUES ($1, $2, 'queued', $3, $4::jsonb)`,
		r.ID, r.Target.Host, r.StartedAt, string(data))
	return err
}

// Claim reserva atomicamente o job elegível mais antigo. SKIP LOCKED faz workers concorrentes
// pularem linhas já travadas por outro, sem bloquear nem reservar o mesmo job.
// Elegível = queued, ou running com lease vencido (worker morreu) e tentativas restantes.
func (p *PostgresRepository) Claim(ctx context.Context, workerID string, lease time.Duration) (*domain.Job, error) {
	var raw []byte
	var attempt int
	err := p.db.QueryRowContext(ctx, `
		WITH next AS (
			SELECT id FROM scans
			 WHERE (status = 'queued'
			        OR (status = 'running' AND (locked_until IS NULL OR locked_until < now())))
			   AND attempts < max_attempts
			 ORDER BY started_at
			 LIMIT 1
			 FOR UPDATE SKIP LOCKED
		)
		UPDATE scans s
		   SET status       = 'running',
		       locked_by    = $1,
		       locked_until = now() + make_interval(secs => $2::float8),
		       attempts     = s.attempts + 1,
		       data         = jsonb_set(s.data, '{status}', '"running"')
		  FROM next
		 WHERE s.id = next.id
		RETURNING s.data, s.attempts`,
		workerID, lease.Seconds()).Scan(&raw, &attempt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var res domain.ScanResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("decodificar job: %w", err)
	}
	return &domain.Job{Result: res, Attempt: attempt}, nil
}

func (p *PostgresRepository) Extend(ctx context.Context, id, workerID string, lease time.Duration) error {
	res, err := p.db.ExecContext(ctx, `
		UPDATE scans
		   SET locked_until = now() + make_interval(secs => $3::float8)
		 WHERE id = $1 AND locked_by = $2 AND status = 'running'`,
		id, workerID, lease.Seconds())
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return domain.ErrLeaseLost
	}
	return nil
}

func (p *PostgresRepository) Finish(ctx context.Context, workerID string, r domain.ScanResult) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	res, err := p.db.ExecContext(ctx, `
		UPDATE scans
		   SET status = $3, finished_at = $4, data = $5::jsonb,
		       locked_by = NULL, locked_until = NULL
		 WHERE id = $1 AND locked_by = $2 AND status = 'running'`,
		r.ID, workerID, string(r.Status), r.FinishedAt, string(data))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return domain.ErrLeaseLost
	}
	return nil
}

func (p *PostgresRepository) ReapExhausted(ctx context.Context) (int64, error) {
	res, err := p.db.ExecContext(ctx, `
		UPDATE scans
		   SET status = 'failed', finished_at = now(), locked_by = NULL, locked_until = NULL,
		       data = jsonb_set(
		                jsonb_set(
		                  jsonb_set(data, '{status}', '"failed"'),
		                  '{finished_at}', to_jsonb(now())),
		                '{errors}',
		                COALESCE(data -> 'errors', '[]'::jsonb)
		                  || '["worker perdeu o lease e as tentativas se esgotaram"]'::jsonb)
		 WHERE status = 'running'
		   AND (locked_until IS NULL OR locked_until < now())
		   AND attempts >= max_attempts`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
