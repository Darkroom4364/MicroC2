package enrollment

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
)

func TestGenerateBootstrapCredentialUsesCanonicalRandomBase64URL(t *testing.T) {
	random := bytes.NewReader(bytes.Repeat([]byte{0xa5}, BootstrapCredentialBytes))
	credential, err := generateBootstrapCredential(random)
	if err != nil {
		t.Fatalf("generate bootstrap credential: %v", err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(credential.Public)
	if err != nil {
		t.Fatalf("decode bootstrap credential: %v", err)
	}
	if len(decoded) != BootstrapCredentialBytes {
		t.Fatalf("bootstrap bytes = %d, want %d", len(decoded), BootstrapCredentialBytes)
	}
	if credential.Public != base64.RawURLEncoding.EncodeToString(decoded) {
		t.Fatal("bootstrap credential is not canonical raw base64url")
	}
	if credential.SHA256 != sha256.Sum256(decoded) {
		t.Fatal("bootstrap hash does not cover decoded secret bytes")
	}
}

func TestGenerateBootstrapCredentialPropagatesEntropyFailure(t *testing.T) {
	_, err := generateBootstrapCredential(errorReader{})
	if err == nil {
		t.Fatal("entropy failure unexpectedly succeeded")
	}
}

func TestParseSessionCredentialIsStrict(t *testing.T) {
	var key [sha256.Size]byte
	var sessionID [SessionIDBytes]byte
	for index := range key {
		key[index] = byte(index + 1)
		sessionID[index] = byte(255 - index)
	}
	valid := encodeSessionCredential(
		key,
		sessionID,
		7,
		"listener-one",
		"agent-one",
		"build-one",
	)
	parsed, err := ParseSessionCredential(valid)
	if err != nil {
		t.Fatalf("parse valid credential: %v", err)
	}
	if parsed.Generation != 7 ||
		parsed.SessionID != base64.RawURLEncoding.EncodeToString(sessionID[:]) {
		t.Fatalf("unexpected parsed credential: %+v", parsed)
	}

	parts := splitCredential(t, valid)
	tests := map[string]string{
		"empty":               "",
		"wrong version":       "s2." + parts[1] + ".7." + parts[3],
		"missing field":       "s1." + parts[1] + "." + parts[3],
		"extra field":         valid + ".extra",
		"padded session":      "s1." + parts[1] + "=.7." + parts[3],
		"invalid session":     "s1.!.7." + parts[3],
		"zero generation":     "s1." + parts[1] + ".0." + parts[3],
		"leading zero":        "s1." + parts[1] + ".07." + parts[3],
		"signed generation":   "s1." + parts[1] + ".+7." + parts[3],
		"overflow generation": "s1." + parts[1] + ".9223372036854775808." + parts[3],
		"padded mac":          "s1." + parts[1] + ".7." + parts[3] + "=",
		"invalid mac":         "s1." + parts[1] + ".7.!",
	}
	for name, credential := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSessionCredential(credential); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("parse error = %v, want ErrUnauthorized", err)
			}
		})
	}
}

func splitCredential(t *testing.T, credential string) []string {
	t.Helper()
	var parts []string
	start := 0
	for index := 0; index < len(credential); index++ {
		if credential[index] == '.' {
			parts = append(parts, credential[start:index])
			start = index + 1
		}
	}
	parts = append(parts, credential[start:])
	if len(parts) != 4 {
		t.Fatalf("credential parts = %d, want 4", len(parts))
	}
	return parts
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}
