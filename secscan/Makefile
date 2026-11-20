BINARY  := secscan
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: deps build test test-db lint run-scan docker up down scale

deps:
	go get github.com/jackc/pgx/v5
	go mod tidy

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o bin/$(BINARY) ./cmd/secscan

test:
	go vet ./...
	go test -race -cover ./...

test-db:   # requer o compose no ar com a porta do banco publicada (veja README)
	SECSCAN_TEST_DATABASE_URL='postgres://secscan:secscan-dev@localhost:5432/secscan?sslmode=disable' go test ./internal/infrastructure/storage/...

lint:
	golangci-lint run

run-scan: build
	./bin/$(BINARY) scan -host scanme.nmap.org -ports 22,80,443,9929 -format markdown

docker:
	docker build --build-arg VERSION=$(VERSION) -t $(BINARY):$(VERSION) .

up:
	docker compose up --build -d

down:
	docker compose down

scale:
	docker compose up -d --scale worker=3
