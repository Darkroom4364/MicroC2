package main

import (
	"bytes"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"testing"
)

func TestHTTPSRedirectTargetUsesConfiguredPortForEveryHost(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{
			name: "localhost with HTTP port",
			host: "localhost:8080",
			want: "https://localhost:8443/home/?tab=agents",
		},
		{
			name: "remote DNS host with HTTP port",
			host: "operator.lab:8080",
			want: "https://operator.lab:8443/home/?tab=agents",
		},
		{
			name: "host without port",
			host: "operator.lab",
			want: "https://operator.lab:8443/home/?tab=agents",
		},
		{
			name: "IPv4 with HTTP port",
			host: "192.0.2.10:8080",
			want: "https://192.0.2.10:8443/home/?tab=agents",
		},
		{
			name: "IPv6 with HTTP port",
			host: "[2001:db8::10]:8080",
			want: "https://[2001:db8::10]:8443/home/?tab=agents",
		},
		{
			name: "IPv6 without port",
			host: "[2001:db8::10]",
			want: "https://[2001:db8::10]:8443/home/?tab=agents",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := &http.Request{
				Host: test.host,
				URL: &url.URL{
					Path:     "/home/",
					RawQuery: "tab=agents",
				},
			}
			if got := httpsRedirectTarget(request, "8443"); got != test.want {
				t.Fatalf("redirect target = %q, want %q", got, test.want)
			}
		})
	}
}

func TestHTTPSRedirectTargetFallsBackForMissingOrMalformedHost(t *testing.T) {
	tests := []*http.Request{
		nil,
		{},
		{Host: "operator.lab", URL: &url.URL{}},
		{URL: &url.URL{Path: "/"}},
		{Host: "malformed:host:value", URL: &url.URL{Path: "/"}},
	}
	wants := []string{
		"https://localhost:8443/",
		"https://localhost:8443/",
		"https://operator.lab:8443/",
		"https://localhost:8443/",
		"https://localhost:8443/",
	}
	for index, request := range tests {
		if got := httpsRedirectTarget(request, "8443"); got != wants[index] {
			t.Fatalf("redirect target = %q, want %q", got, wants[index])
		}
	}
}

func TestLogHTTPSRedirectRemovesControlCharacters(t *testing.T) {
	originalOutput := log.Writer()
	originalFlags := log.Flags()
	originalPrefix := log.Prefix()
	t.Cleanup(func() {
		log.SetOutput(originalOutput)
		log.SetFlags(originalFlags)
		log.SetPrefix(originalPrefix)
	})

	var output bytes.Buffer
	log.SetOutput(&output)
	log.SetFlags(0)
	log.SetPrefix("")

	logHTTPSRedirect(
		"/safe?next=ok\r\n[FORGED]\x00\x1b\t\u2028\u202e",
		"https://operator.lab:8443/safe\r\n[FORGED]\u2029",
	)

	const want = "[REDIRECT] /safe?next=ok[FORGED] -> " +
		"https://operator.lab:8443/safe[FORGED]\n"
	if got := output.String(); got != want {
		t.Fatalf("redirect log = %q, want %q", got, want)
	}
}

func TestBindServerListenersBindsEveryConfiguredSocketBeforeServing(t *testing.T) {
	httpsListener := &stubListener{}
	redirectListener := &stubListener{}
	var addresses []string
	listen := func(_, address string) (net.Listener, error) {
		addresses = append(addresses, address)
		switch address {
		case ":8443":
			return httpsListener, nil
		case ":8080":
			return redirectListener, nil
		default:
			t.Fatalf("unexpected listen address %q", address)
			return nil, nil
		}
	}

	bound, err := bindServerListeners(":8443", ":8080", true, listen)
	if err != nil {
		t.Fatalf("bind configured listeners: %v", err)
	}
	if bound.https != httpsListener || bound.redirect != redirectListener {
		t.Fatal("bound listener set did not preserve both configured sockets")
	}
	if len(addresses) != 2 ||
		addresses[0] != ":8443" ||
		addresses[1] != ":8080" {
		t.Fatalf("listen addresses = %#v, want [:8443 :8080]", addresses)
	}

	bound.close()
	if !httpsListener.closed || !redirectListener.closed {
		t.Fatal("operator listener cleanup did not close every bound socket")
	}
}

func TestBindServerListenersClosesHTTPSSocketWhenRedirectBindFails(t *testing.T) {
	httpsListener := &stubListener{}
	redirectBindError := errors.New("redirect address unavailable")
	listen := func(_ string, address string) (net.Listener, error) {
		if address == ":8443" {
			return httpsListener, nil
		}
		return nil, redirectBindError
	}

	bound, err := bindServerListeners(":8443", ":8080", true, listen)
	if !errors.Is(err, redirectBindError) {
		t.Fatalf("bind error = %v, want redirect bind failure", err)
	}
	if bound.https != nil || bound.redirect != nil {
		t.Fatal("partial listener set escaped a failed startup bind")
	}
	if !httpsListener.closed {
		t.Fatal("HTTPS socket remained bound after redirect bind failure")
	}
}

func TestBindServerListenersSkipsRedirectWhenDisabled(t *testing.T) {
	httpsListener := &stubListener{}
	listenCalls := 0
	listen := func(_ string, address string) (net.Listener, error) {
		listenCalls++
		if address != ":8443" {
			t.Fatalf("unexpected listen address %q", address)
		}
		return httpsListener, nil
	}

	bound, err := bindServerListeners(":8443", "", false, listen)
	if err != nil {
		t.Fatalf("bind HTTPS listener: %v", err)
	}
	defer bound.close()
	if listenCalls != 1 || bound.https != httpsListener || bound.redirect != nil {
		t.Fatalf(
			"disabled redirect binding = calls:%d listeners:%#v",
			listenCalls,
			bound,
		)
	}
}

type stubListener struct {
	closed bool
}

func (listener *stubListener) Accept() (net.Conn, error) {
	return nil, errors.New("unexpected Accept call")
}

func (listener *stubListener) Close() error {
	listener.closed = true
	return nil
}

func (listener *stubListener) Addr() net.Addr {
	return stubAddr("stub")
}

type stubAddr string

func (addr stubAddr) Network() string {
	return "tcp"
}

func (addr stubAddr) String() string {
	return string(addr)
}
