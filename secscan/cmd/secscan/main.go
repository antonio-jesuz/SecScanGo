// Comando secscan: CLI e servidor de API do Security Scanner.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/antonio-jesuz/secscan/internal/application"
	"github.com/antonio-jesuz/secscan/internal/domain"
	"github.com/antonio-jesuz/secscan/internal/infrastructure/observability"
	"github.com/antonio-jesuz/secscan/internal/infrastructure/report"
	"github.com/antonio-jesuz/secscan/internal/infrastructure/scanners"
	"github.com/antonio-jesuz/secscan/internal/infrastructure/storage"
	"github.com/antonio-jesuz/secscan/internal/interfaces/httpapi"
)

var version = "dev" // injetado via -ldflags

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "scan":
		os.Exit(runScan(os.Args[2:]))
	case "serve":
		os.Exit(runServe(os.Args[2:]))
	case "worker":
		os.Exit(runWorker(os.Args[2:]))
	case "healthcheck":
		os.Exit(runHealthcheck())
	case "version":
		fmt.Println("secscan", version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `SecScan - Security Scanner

Uso:
  secscan scan -host <alvo> [-ports 22,80,8000-8100] [-format text|json|markdown] [-fail-on high]
  secscan serve [-addr :8080]            API REST (com SECSCAN_DATABASE_URL, apenas enfileira)
  secscan worker [-concurrency 2]        consome a fila e executa as varreduras (exige PostgreSQL)
  secscan healthcheck
  secscan version

Use SOMENTE contra sistemas que você possui ou tem autorização por escrito para testar.
`)
}

// composition root: único lugar que conhece todas as camadas.
func buildService(repo domain.ScanRepository, log *slog.Logger, allowPrivate bool, timeout time.Duration, obs application.Observer) *application.Service {
	scs := []domain.Scanner{
		scanners.NewPortScanner(),
		scanners.NewTLSScanner(),
		scanners.NewHeadersScanner(),
	}
	svc := application.NewService(scs, repo, application.TargetPolicy{AllowPrivate: allowPrivate}, log, timeout, obs)
	// Se o repositório também é uma fila (PostgreSQL), a API só enfileira; workers executam.
	if q, ok := repo.(domain.JobQueue); ok {
		svc.UseQueue(q)
	}
	return svc
}

// buildRepo usa PostgreSQL quando SECSCAN_DATABASE_URL está definida; senão, memória.
func buildRepo(ctx context.Context, log *slog.Logger) (domain.ScanRepository, func(), error) {
	url := os.Getenv("SECSCAN_DATABASE_URL")
	if url == "" {
		log.Warn("SECSCAN_DATABASE_URL vazio: usando armazenamento em memória (dados somem ao reiniciar)")
		return storage.NewMemoryRepository(), func() {}, nil
	}
	pg, err := storage.OpenPostgres(ctx, url)
	if err != nil {
		return nil, nil, err
	}
	log.Info("armazenamento PostgreSQL conectado")
	return pg, func() { _ = pg.Close() }, nil
}

func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	host := fs.String("host", "", "host ou IP alvo (obrigatório)")
	portsSpec := fs.String("ports", "", "portas: 22,80,8000-8100 (padrão: lista comum)")
	format := fs.String("format", "text", "text | json | markdown")
	timeout := fs.Duration("timeout", 60*time.Second, "tempo máximo da varredura")
	allowPrivate := fs.Bool("allow-private", envBool("SECSCAN_ALLOW_PRIVATE"), "permitir loopback/redes privadas")
	failOn := fs.String("fail-on", "", "sai com código 1 se houver achado >= severidade (info|low|medium|high|critical)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *host == "" {
		fmt.Fprintln(os.Stderr, "erro: -host é obrigatório")
		fs.Usage()
		return 2
	}
	if !report.Supported(*format) {
		fmt.Fprintln(os.Stderr, "erro: -format deve ser text, json ou markdown")
		return 2
	}
	ports, err := application.ParsePorts(*portsSpec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "erro:", err)
		return 2
	}
	var threshold domain.Severity
	if *failOn != "" {
		if threshold, err = domain.ParseSeverity(*failOn); err != nil {
			fmt.Fprintln(os.Stderr, "erro:", err)
			return 2
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	svc := buildService(storage.NewMemoryRepository(), log, *allowPrivate, *timeout, nil)

	res, err := svc.Run(ctx, domain.Target{Host: *host, Ports: ports})
	if err != nil {
		fmt.Fprintln(os.Stderr, "erro:", err)
		return 2
	}
	if err := report.Write(os.Stdout, *format, res); err != nil {
		fmt.Fprintln(os.Stderr, "erro ao gerar relatório:", err)
		return 2
	}
	if *failOn != "" {
		if highest, ok := res.MaxSeverity(); ok && highest >= threshold {
			return 1
		}
	}
	return 0
}

func runServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", envStr("SECSCAN_ADDR", ":8080"), "endereço de escuta")
	allowPrivate := fs.Bool("allow-private", envBool("SECSCAN_ALLOW_PRIVATE"), "permitir loopback/redes privadas")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	metrics := observability.NewMetrics()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	repo, closeRepo, err := buildRepo(ctx, log)
	if err != nil {
		log.Error("falha ao iniciar armazenamento", "err", err)
		return 1
	}
	defer closeRepo()
	svc := buildService(repo, log, *allowPrivate, 2*time.Minute, metrics)
	if _, ok := repo.(domain.JobQueue); ok {
		log.Warn("modo fila ativo: a API só enfileira; inicie ao menos um worker (secscan worker)")
	}

	apiKey := os.Getenv("SECSCAN_API_KEY")
	if apiKey == "" {
		log.Warn("SECSCAN_API_KEY vazio: a API está SEM autenticação")
	}
	api := httpapi.New(svc, repo, log, apiKey, metrics.Handler())

	srv := &http.Server{
		Addr:              *addr,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("servidor iniciado", "addr", *addr, "version", version)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Error("servidor falhou", "err", err)
			return 1
		}
	case <-ctx.Done():
		log.Info("encerrando (graceful shutdown)")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		svc.Wait()
	}
	return 0
}

// runWorker consome a fila de varreduras. Pode rodar em N réplicas.
func runWorker(args []string) int {
	fs := flag.NewFlagSet("worker", flag.ContinueOnError)
	addr := fs.String("addr", envStr("SECSCAN_ADDR", ":9100"), "endereço de /healthz e /metrics do worker")
	allowPrivate := fs.Bool("allow-private", envBool("SECSCAN_ALLOW_PRIVATE"), "permitir loopback/redes privadas")
	concurrency := fs.Int("concurrency", envInt("SECSCAN_WORKER_CONCURRENCY", 2), "varreduras simultâneas neste worker")
	lease := fs.Duration("lease", 30*time.Second, "validade do lease de um job (renovado por heartbeat)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if os.Getenv("SECSCAN_DATABASE_URL") == "" {
		log.Error("o worker exige SECSCAN_DATABASE_URL (a fila vive no PostgreSQL)")
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	repo, closeRepo, err := buildRepo(ctx, log)
	if err != nil {
		log.Error("falha ao iniciar armazenamento", "err", err)
		return 1
	}
	defer closeRepo()
	queue, ok := repo.(domain.JobQueue)
	if !ok {
		log.Error("o repositório configurado não implementa fila")
		return 1
	}

	metrics := observability.NewMetrics()
	svc := buildService(repo, log, *allowPrivate, 2*time.Minute, metrics)

	host, _ := os.Hostname()
	w := application.NewWorker(svc, queue, application.WorkerConfig{
		ID:          fmt.Sprintf("%s-%d", host, os.Getpid()),
		Concurrency: *concurrency,
		Lease:       *lease,
	}, log)

	// Servidor mínimo para healthcheck do container e scrape do Prometheus.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write([]byte(`{"status":"ok"}`))
	})
	mux.Handle("GET /metrics", metrics.Handler())
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("servidor de métricas falhou", "err", err)
		}
	}()

	log.Info("worker iniciado", "version", version, "concurrency", *concurrency, "lease", lease.String())
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	<-ctx.Done()
	log.Info("encerrando worker: sem novos jobs; aguardando os em andamento (até 30s)")
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		log.Warn("grace excedido; os leases expirarão e outro worker reexecutará esses jobs")
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	return 0
}

// runHealthcheck existe porque a imagem distroless não tem curl/wget.
func runHealthcheck() int {
	addr := envStr("SECSCAN_ADDR", ":8080")
	if len(addr) > 0 && addr[0] == ':' {
		addr = "127.0.0.1" + addr
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + addr + "/healthz")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envBool(key string) bool {
	switch os.Getenv(key) {
	case "1", "true", "TRUE", "True", "yes":
		return true
	}
	return false
}
