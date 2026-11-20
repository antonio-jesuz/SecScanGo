package scanners

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/antonio-jesuz/secscan/internal/domain"
)

func TestPortScannerFindsOpenPortOnly(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	openPort := ln.Addr().(*net.TCPAddr).Port

	// reserva uma porta e a fecha em seguida: garantidamente fechada
	tmp, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := tmp.Addr().(*net.TCPAddr).Port
	tmp.Close()

	ps := &PortScanner{Timeout: time.Second, Workers: 4}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := ps.Scan(ctx, domain.Target{Host: "127.0.0.1", Ports: []int{openPort, closedPort}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("esperava 1 achado, veio %d: %+v", len(got), got)
	}
}
