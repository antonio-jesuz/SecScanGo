// Package scanners contém as implementações concretas de domain.Scanner.
package scanners

import (
	"net"
	"strings"
)

func hostOnly(hp string) string {
	if h, _, err := net.SplitHostPort(hp); err == nil {
		return h
	}
	return strings.Trim(hp, "[]")
}

func hostWithPort(hp, defaultPort string) string {
	if _, _, err := net.SplitHostPort(hp); err == nil {
		return hp
	}
	return net.JoinHostPort(strings.Trim(hp, "[]"), defaultPort)
}
