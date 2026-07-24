package common

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrInsecureHTTPAgentTransport identifies an HTTP agent listener that was
	// rejected by the production transport policy.
	ErrInsecureHTTPAgentTransport = errors.New("insecure HTTP agent transport is disabled")

	// ErrClientCertificateValidationUnavailable identifies a request for mTLS
	// before MicroC2 has a CA-backed client-certificate verifier.
	ErrClientCertificateValidationUnavailable = errors.New("agent client-certificate validation is not implemented")
)

// AgentTransportPolicy controls security-sensitive listener construction.
// The zero value is the production-safe policy.
type AgentTransportPolicy struct {
	// AllowInsecureIsolatedLab permits plaintext HTTP agent listeners. This is
	// an explicit escape hatch for isolated labs and must remain false in
	// production.
	AllowInsecureIsolatedLab bool
}

// IsolatedLabAgentTransportPolicy returns the compatibility policy used only
// by explicitly named lab/test constructors.
func IsolatedLabAgentTransportPolicy() AgentTransportPolicy {
	return AgentTransportPolicy{AllowInsecureIsolatedLab: true}
}

// ValidateListener rejects transport configurations that cannot meet the
// policy. HTTPS listener TLS configuration is enforced by the listener
// runtime; client-certificate authentication is rejected until a real
// CA-backed verifier exists.
func (p AgentTransportPolicy) ValidateListener(
	protocol string,
	requireClientCert bool,
) error {
	if requireClientCert {
		return fmt.Errorf(
			"%w; requireClientCert cannot be enabled until CA-backed mTLS is available",
			ErrClientCertificateValidationUnavailable,
		)
	}
	if strings.EqualFold(strings.TrimSpace(protocol), "http") &&
		!p.AllowInsecureIsolatedLab {
		return fmt.Errorf(
			"%w; set security.agentTransport.allowInsecureIsolatedLab=true only for an isolated lab",
			ErrInsecureHTTPAgentTransport,
		)
	}
	return nil
}
