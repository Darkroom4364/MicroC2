package common

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// IsLoopbackHost reports whether the given host (with optional port) refers
// to a loopback address or localhost.
func IsLoopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type httpOrigin struct {
	scheme string
	host   string
	port   int
}

// ValidateHTTPOrigin validates the exact origin syntax accepted by the
// operator and agent-listener browser policies. An origin contains only an
// HTTP(S) scheme, host, and optional port; paths and other URL components are
// deliberately rejected.
func ValidateHTTPOrigin(raw string) error {
	_, err := parseHTTPOrigin(raw)
	return err
}

// IsOriginAllowed reports whether a request with the given Origin header may
// proceed. Requests without an Origin header (non-browser clients such as
// curl or the agent) are always allowed. Browser origins are allowed when
// their scheme, host, and effective port match the request or a configured
// allow-list entry. A "*" entry is an explicit escape hatch that accepts any
// origin.
func IsOriginAllowed(origin string, request *http.Request, allowed []string) bool {
	if origin == "" {
		return true
	}
	for _, entry := range allowed {
		if entry == "*" {
			return true
		}
	}

	parsedOrigin, err := parseHTTPOrigin(origin)
	if err != nil {
		return false
	}
	for _, entry := range allowed {
		parsedEntry, err := parseHTTPOrigin(entry)
		if err == nil && parsedOrigin == parsedEntry {
			return true
		}
	}
	requestOrigin, err := httpRequestOrigin(request)
	return err == nil && parsedOrigin == requestOrigin
}

func parseHTTPOrigin(raw string) (httpOrigin, error) {
	if raw == "" ||
		raw != strings.TrimSpace(raw) ||
		strings.Contains(raw, "#") {
		return httpOrigin{}, errorsForHTTPOrigin()
	}
	parsed, err := url.Parse(raw)
	if err != nil ||
		parsed.Opaque != "" ||
		parsed.User != nil ||
		parsed.Host == "" ||
		parsed.Path != "" ||
		parsed.RawPath != "" ||
		parsed.RawQuery != "" ||
		parsed.ForceQuery ||
		parsed.Fragment != "" ||
		parsed.RawFragment != "" {
		return httpOrigin{}, errorsForHTTPOrigin()
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return httpOrigin{}, errorsForHTTPOrigin()
	}
	host, err := normalizeHTTPOriginHost(parsed)
	if err != nil {
		return httpOrigin{}, err
	}

	port := 80
	if scheme == "https" {
		port = 443
	}
	if explicitPort := parsed.Port(); explicitPort != "" {
		port, err = strconv.Atoi(explicitPort)
		if err != nil || port < 1 || port > 65535 {
			return httpOrigin{}, errorsForHTTPOrigin()
		}
	} else if strings.HasSuffix(parsed.Host, ":") {
		return httpOrigin{}, errorsForHTTPOrigin()
	}

	return httpOrigin{scheme: scheme, host: host, port: port}, nil
}

func normalizeHTTPOriginHost(parsed *url.URL) (string, error) {
	host := parsed.Hostname()
	if host == "" || strings.Contains(host, "%") {
		return "", errorsForHTTPOrigin()
	}

	bracketed := strings.HasPrefix(parsed.Host, "[")
	ip := net.ParseIP(host)
	if bracketed {
		// Brackets are canonical only for IPv6 literals.
		if ip == nil || ip.To4() != nil {
			return "", errorsForHTTPOrigin()
		}
		return ip.String(), nil
	}
	if strings.Contains(host, ":") {
		// IPv6 literals must be bracketed so their colons cannot be confused
		// with the optional origin port.
		return "", errorsForHTTPOrigin()
	}
	if ip != nil {
		return ip.String(), nil
	}
	if !isValidDNSName(host) {
		return "", errorsForHTTPOrigin()
	}
	return strings.ToLower(host), nil
}

func isValidDNSName(host string) bool {
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 ||
			!isASCIIAlphaNumeric(label[0]) ||
			!isASCIIAlphaNumeric(label[len(label)-1]) {
			return false
		}
		for index := 1; index < len(label)-1; index++ {
			if !isASCIIAlphaNumeric(label[index]) && label[index] != '-' {
				return false
			}
		}
	}
	return true
}

func isASCIIAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9'
}

func httpRequestOrigin(request *http.Request) (httpOrigin, error) {
	if request == nil || request.Host == "" {
		return httpOrigin{}, errorsForHTTPOrigin()
	}
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	return parseHTTPOrigin(scheme + "://" + request.Host)
}

func errorsForHTTPOrigin() error {
	return fmt.Errorf(
		`must be "*" or a canonical http(s) origin containing only scheme, host, and optional port`,
	)
}
