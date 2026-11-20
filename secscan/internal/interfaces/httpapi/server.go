// Package httpapi é a camada de entrega REST. Só fala com application/domain via contratos.
package httpapi

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/antonio-jesuz/secscan/internal/application"
	"github.com/antonio-jesuz/secscan/internal/domain"
	"github.com/antonio-jesuz/secscan/internal/infrastructure/report"
)

type Server struct {
	svc     *application.Service
	repo    domain.ScanRepository
	log     *slog.Logger
	apiKey  string
	metrics http.Handler
}

func New(svc *application.Service, repo domain.ScanRepository, log *slog.Logger, apiKey string, metrics http.Handler) *Server {
	return &Server{svc: svc, repo: repo, log: log, apiKey: apiKey, metrics: metrics}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.Handle("GET /metrics", s.metrics)
	mux.Handle("POST /v1/scans", s.auth(http.HandlerFunc(s.createScan)))
	mux.Handle("GET /v1/scans", s.auth(http.HandlerFunc(s.listScans)))
	mux.Handle("GET /v1/scans/{id}", s.auth(http.HandlerFunc(s.getScan)))
	mux.Handle("GET /v1/scans/{id}/report", s.auth(http.HandlerFunc(s.getReport)))
	return chain(mux, s.recoverer, s.logging)
}

type createScanRequest struct {
	Host  string `json:"host"`
	Ports string `json:"ports"` // ex.: "22,80,8000-8100"
}

func (s *Server) createScan(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var req createScanRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "JSON inválido: "+err.Error())
		return
	}
	ports, err := application.ParsePorts(req.Ports)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := s.svc.Submit(r.Context(), domain.Target{Host: req.Host, Ports: ports})
	switch {
	case errors.Is(err, application.ErrInvalidTarget):
		writeError(w, http.StatusBadRequest, err.Error())
		return
	case errors.Is(err, application.ErrTargetNotAllowed):
		writeError(w, http.StatusForbidden, err.Error())
		return
	case err != nil:
		s.log.Error("falha ao criar varredura", "err", err)
		writeError(w, http.StatusInternalServerError, "erro interno")
		return
	}
	w.Header().Set("Location", "/v1/scans/"+res.ID)
	writeJSON(w, http.StatusAccepted, res)
}

func (s *Server) listScans(w http.ResponseWriter, r *http.Request) {
	list, err := s.repo.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "erro interno")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) getScan(w http.ResponseWriter, r *http.Request) {
	res, err := s.repo.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, domain.ErrNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "erro interno")
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) getReport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "markdown"
	}
	if !report.Supported(format) {
		writeError(w, http.StatusBadRequest, "format deve ser text, json ou markdown")
		return
	}
	res, err := s.repo.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, domain.ErrNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "erro interno")
		return
	}
	ct := map[string]string{"json": "application/json", "markdown": "text/markdown", "text": "text/plain"}[format]
	w.Header().Set("Content-Type", ct+"; charset=utf-8")
	_ = report.Write(w, format, res)
}

// --- middlewares ---

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.apiKey != "" {
			got := r.Header.Get("X-API-Key")
			if subtle.ConstantTimeCompare([]byte(got), []byte(s.apiKey)) != 1 {
				writeError(w, http.StatusUnauthorized, "API key ausente ou inválida")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (s *Server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.log.Info("http", "method", r.Method, "path", r.URL.Path, "status", rec.status,
			"duration", time.Since(start).String(), "remote", r.RemoteAddr)
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic no handler", "panic", rec)
				writeError(w, http.StatusInternalServerError, "erro interno")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
