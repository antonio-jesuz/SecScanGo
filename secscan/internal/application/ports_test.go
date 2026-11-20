package application

import (
	"reflect"
	"testing"
)

func TestParsePorts(t *testing.T) {
	tests := []struct {
		in      string
		want    []int
		wantErr bool
	}{
		{"", nil, false},
		{"80,22,80", []int{22, 80}, false},
		{"8000-8002, 443", []int{443, 8000, 8001, 8002}, false},
		{"0", nil, true},
		{"70000", nil, true},
		{"90-80", nil, true},
		{"abc", nil, true},
		{"1-20000", nil, true},
	}
	for _, tc := range tests {
		got, err := ParsePorts(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParsePorts(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			continue
		}
		if !tc.wantErr && !reflect.DeepEqual(got, tc.want) {
			t.Errorf("ParsePorts(%q) = %v, quer %v", tc.in, got, tc.want)
		}
	}
}
