package common

import (
	"net"
	"net/url"
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

// IsOriginAllowed reports whether a request with the given Origin header may
// proceed. Requests without an Origin header (non-browser clients such as
// curl or the agent) are always allowed. Browser origins are allowed when
// they match the request host or appear in the configured allow list. A "*"
// entry in the allow list is an explicit escape hatch that accepts any
// origin.
func IsOriginAllowed(origin, requestHost string, allowed []string) bool {
	if origin == "" {
		return true
	}
	for _, entry := range allowed {
		if entry == "*" {
			return true
		}
	}
	originHost := origin
	if u, err := url.Parse(origin); err == nil && u.Host != "" {
		originHost = u.Host
	}
	for _, entry := range allowed {
		entryHost := entry
		if u, err := url.Parse(entry); err == nil && u.Host != "" {
			entryHost = u.Host
		}
		if strings.EqualFold(originHost, entryHost) {
			return true
		}
	}
	if strings.EqualFold(originHost, requestHost) {
		return true
	}
	return false
}
