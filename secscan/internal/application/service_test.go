package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/antonio-jesuz/secscan/internal/domain"
	"github.com/antonio-jesuz/secscan/internal/infrastructure/storage"
)

type fakeScanner struct {
	name string
	f    []domain.Finding
	err  error
}

func (s fakeScanner) Name() string { return s.name }
func (s fakeScanner) Scan(context.Context, domain.Target) ([]domain.Finding, error) {
	return s.f, s.err
}

func TestServiceRunSortsAndPersists(t *testing.T) {
	repo := storage.NewMemoryRepository()
	svc := NewService([]domain.Scanner{
		fakeScanner{name: "a", f: []domain.Finding{{ID: "LOW-1", Severity: domain.SeverityLow}}},
		fakeScanner{name: "b", f: []domain.Finding{{ID: "HIGH-1", Severity: domain.SeverityHigh}}},
		fakeScanner{name: "c", err: errors.New("boom")},
	}, repo, TargetPolicy{AllowPrivate: true}, nil, 5*time.Second, nil)

	res, err := svc.Run(context.Background(), domain.Target{Host: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != domain.StatusCompleted {
		t.Errorf("status = %s, quer completed (falha parcial não derruba a varredura)", res.Status)
	}
	if len(res.Findings) != 2 || res.Findings[0].ID != "HIGH-1" {
		t.Errorf("achados não ordenados por severidade: %+v", res.Findings)
	}
	if len(res.Errors) != 1 {
		t.Errorf("esperava 1 erro registrado, veio %v", res.Errors)
	}
	saved, err := repo.Get(context.Background(), res.ID)
	if err != nil || saved.Status != domain.StatusCompleted {
		t.Errorf("resultado não persistido: %v %v", saved.Status, err)
	}
}

func TestServiceRejectsBlockedTarget(t *testing.T) {
	svc := NewService(nil, storage.NewMemoryRepository(), TargetPolicy{}, nil, time.Second, nil)
	if _, err := svc.Run(context.Background(), domain.Target{Host: "127.0.0.1"}); !errors.Is(err, ErrTargetNotAllowed) {
		t.Errorf("err = %v", err)
	}
}
