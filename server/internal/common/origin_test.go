package common

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

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
		requestURL  string
		requestHost string
		allowed     []string
		want        bool
	}{
		{"no origin header is allowed (non-browser client)", "", "https://localhost:8443/", "localhost:8443", nil, true},
		{"same origin", "https://localhost:8443", "https://localhost:8443/", "localhost:8443", nil, true},
		{"same host with wrong scheme", "http://localhost:8443", "https://localhost:8443/", "localhost:8443", nil, false},
		{"default HTTPS port is normalized", "https://localhost:443", "https://localhost/", "localhost", nil, true},
		{"loopback origin must be configured for a remote host", "http://127.0.0.1:8080", "https://example.com:8443/", "example.com:8443", nil, false},
		{"configured loopback origin", "http://127.0.0.1:8080", "https://example.com:8443/", "example.com:8443", []string{"http://127.0.0.1:8080"}, true},
		{"configured origin", "https://operator.lab:9443", "https://c2.lab:8443/", "c2.lab:8443", []string{"https://operator.lab:9443"}, true},
		{"configured host without scheme is invalid", "https://operator.lab:9443", "https://c2.lab:8443/", "c2.lab:8443", []string{"operator.lab:9443"}, false},
		{"configured origin with wrong scheme", "http://operator.lab:9443", "https://c2.lab:8443/", "c2.lab:8443", []string{"https://operator.lab:9443"}, false},
		{"disallowed origin", "https://evil.example", "https://c2.lab:8443/", "c2.lab:8443", []string{"https://operator.lab:9443"}, false},
		{"disallowed origin with empty list", "https://evil.example", "https://c2.lab:8443/", "c2.lab:8443", nil, false},
		{"wildcard escape hatch", "https://evil.example", "https://c2.lab:8443/", "c2.lab:8443", []string{"*"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, tt.requestURL, nil)
			request.Host = tt.requestHost
			if got := IsOriginAllowed(tt.origin, request, tt.allowed); got != tt.want {
				t.Fatalf("IsOriginAllowed(%q, %q, %v) = %v, want %v",
					tt.origin, tt.requestHost, tt.allowed, got, tt.want)
			}
		})
	}
}

func TestValidateHTTPOrigin(t *testing.T) {
	for _, valid := range []string{
		"http://operator.lab",
		"https://Operator-Lab",
		"https://operator.lab:9443",
		"https://127.0.0.1",
		"https://[2001:db8::1]",
	} {
		if err := ValidateHTTPOrigin(valid); err != nil {
			t.Fatalf("ValidateHTTPOrigin(%q): %v", valid, err)
		}
	}
	for _, invalid := range []string{
		"",
		"operator.lab",
		"ftp://operator.lab",
		"https://operator.lab/",
		"https://user@operator.lab",
		"https://operator.lab/path",
		"https://operator.lab?query",
		"https://operator.lab#",
		"https://operator.lab:70000",
		"https://.example.com",
		"https://example..com",
		"https://example.com.",
		"https://bad_host.example",
		"https://-example.com",
		"https://example-.com",
		"https://exa\x01mple.com",
		"https://éxample.com",
		"https://[example.com]",
		"https://[127.0.0.1]",
		"https://2001:db8::1",
	} {
		if err := ValidateHTTPOrigin(invalid); err == nil {
			t.Fatalf("ValidateHTTPOrigin(%q) unexpectedly succeeded", invalid)
		}
	}
}
