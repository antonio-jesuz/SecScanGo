package application

import (
	"context"
	"errors"
	"testing"
)

func TestTargetPolicy(t *testing.T) {
	ctx := context.Background()
	strict := TargetPolicy{}
	lax := TargetPolicy{AllowPrivate: true}

	if err := strict.Validate(ctx, "127.0.0.1"); !errors.Is(err, ErrTargetNotAllowed) {
		t.Errorf("loopback deveria ser bloqueado, err = %v", err)
	}
	if err := strict.Validate(ctx, "10.0.0.5:8080"); !errors.Is(err, ErrTargetNotAllowed) {
		t.Errorf("rede privada deveria ser bloqueada, err = %v", err)
	}
	if err := lax.Validate(ctx, "127.0.0.1"); err != nil {
		t.Errorf("loopback com AllowPrivate deveria passar, err = %v", err)
	}
	// metadata de cloud: sempre bloqueado, mesmo com AllowPrivate
	if err := lax.Validate(ctx, "169.254.169.254"); !errors.Is(err, ErrTargetNotAllowed) {
		t.Errorf("link-local deveria ser sempre bloqueado, err = %v", err)
	}
	for _, bad := range []string{"", "http://evil.com", "a b", "user@host"} {
		if err := lax.Validate(ctx, bad); !errors.Is(err, ErrInvalidTarget) {
			t.Errorf("Validate(%q) deveria ser ErrInvalidTarget, err = %v", bad, err)
		}
	}
}
