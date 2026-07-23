package common

import "testing"

func TestIsLoopbackHost(t *testing.T) {
	loopback := []string{
		"127.0.0.1", "127.0.0.1:8443", "::1", "[::1]:8443",
		"localhost", "localhost:8080", "LOCALHOST",
	}
	for _, host := range loopback {
		if !IsLoopbackHost(host) {
			t.Errorf("expected %q to be loopback", host)
		}
	}

	nonLoopback := []string{"192.168.1.10", "10.0.0.5:8443", "example.com", "192.0.2.1:1234"}
	for _, host := range nonLoopback {
		if IsLoopbackHost(host) {
			t.Errorf("expected %q to be non-loopback", host)
		}
	}
}

func TestIsOriginAllowed(t *testing.T) {
	tests := []struct {
		name        string
		origin      string
		requestHost string
		allowed     []string
		want        bool
	}{
		{"no origin header is allowed (non-browser client)", "", "localhost:8443", nil, true},
		{"same host origin", "https://localhost:8443", "localhost:8443", nil, true},
		{"loopback origin must be configured for a remote host", "http://127.0.0.1:8080", "example.com:8443", nil, false},
		{"configured loopback origin", "http://127.0.0.1:8080", "example.com:8443", []string{"http://127.0.0.1:8080"}, true},
		{"configured origin", "https://operator.lab:9443", "c2.lab:8443", []string{"https://operator.lab:9443"}, true},
		{"configured origin by host", "https://operator.lab:9443", "c2.lab:8443", []string{"operator.lab:9443"}, true},
		{"disallowed origin", "https://evil.example", "c2.lab:8443", []string{"https://operator.lab:9443"}, false},
		{"disallowed origin with empty list", "https://evil.example", "c2.lab:8443", nil, false},
		{"wildcard escape hatch", "https://evil.example", "c2.lab:8443", []string{"*"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsOriginAllowed(tt.origin, tt.requestHost, tt.allowed); got != tt.want {
				t.Fatalf("IsOriginAllowed(%q, %q, %v) = %v, want %v",
					tt.origin, tt.requestHost, tt.allowed, got, tt.want)
			}
		})
	}
}
