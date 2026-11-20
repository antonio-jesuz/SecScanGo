// Package application orquestra os casos de uso. Depende apenas de domain.
package application

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

var (
	ErrInvalidTarget    = errors.New("alvo inválido")
	ErrTargetNotAllowed = errors.New("alvo não permitido pela política")
)

var hostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

// TargetPolicy protege contra uso indevido (ex.: SSRF contra metadata de cloud).
// Sempre bloqueia link-local (169.254.0.0/16), multicast e 0.0.0.0.
// Loopback e redes privadas só são aceitos com AllowPrivate.
type TargetPolicy struct {
	AllowPrivate bool
	Resolver     *net.Resolver
}

func (p TargetPolicy) Validate(ctx context.Context, hostport string) error {
	host := strings.TrimSpace(hostport)
	if host == "" || len(host) > 255 || strings.ContainsAny(host, " /\\@?#") {
		return fmt.Errorf("%w: host vazio ou com caracteres inválidos", ErrInvalidTarget)
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")

	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		if !hostnameRe.MatchString(host) {
			return fmt.Errorf("%w: hostname malformado", ErrInvalidTarget)
		}
		r := p.Resolver
		if r == nil {
			r = net.DefaultResolver
		}
		addrs, err := r.LookupIPAddr(ctx, host)
		if err != nil || len(addrs) == 0 {
			return fmt.Errorf("%w: não foi possível resolver %q", ErrInvalidTarget, host)
		}
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
	}
	for _, ip := range ips {
		if err := p.checkIP(ip); err != nil {
			return err
		}
	}
	return nil
}

func (p TargetPolicy) checkIP(ip net.IP) error {
	switch {
	case ip.IsUnspecified(), ip.IsMulticast(), ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return fmt.Errorf("%w: %s é um endereço sempre bloqueado", ErrTargetNotAllowed, ip)
	case (ip.IsLoopback() || ip.IsPrivate()) && !p.AllowPrivate:
		return fmt.Errorf("%w: %s é rede privada/loopback (use SECSCAN_ALLOW_PRIVATE=true)", ErrTargetNotAllowed, ip)
	}
	return nil
}
