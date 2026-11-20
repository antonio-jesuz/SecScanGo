package application

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const maxPorts = 10000

// ParsePorts interpreta "22,80,8000-8100" em uma lista ordenada e sem duplicatas.
func ParsePorts(spec string) ([]int, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, nil
	}
	seen := make(map[int]struct{})
	var out []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi := 0, 0
		if a, b, isRange := strings.Cut(part, "-"); isRange {
			l, err1 := strconv.Atoi(strings.TrimSpace(a))
			h, err2 := strconv.Atoi(strings.TrimSpace(b))
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("%w: faixa de portas %q", ErrInvalidTarget, part)
			}
			lo, hi = l, h
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("%w: porta %q", ErrInvalidTarget, part)
			}
			lo, hi = p, p
		}
		if lo < 1 || hi > 65535 || lo > hi {
			return nil, fmt.Errorf("%w: porta fora do intervalo 1-65535 (%q)", ErrInvalidTarget, part)
		}
		for p := lo; p <= hi; p++ {
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				out = append(out, p)
				if len(out) > maxPorts {
					return nil, fmt.Errorf("%w: máximo de %d portas por varredura", ErrInvalidTarget, maxPorts)
				}
			}
		}
	}
	sort.Ints(out)
	return out, nil
}
