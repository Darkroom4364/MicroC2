package enrollment

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"io"
	"strconv"
	"strings"
)

const (
	sessionCredentialVersion = "s1"
	sessionMACDomain         = "microc2-agent-session-v1"
)

var invalidBootstrapDigest = sha256.Sum256([]byte("invalid bootstrap credential"))

type parsedSessionCredential struct {
	public     ParsedSessionCredential
	sessionID  [SessionIDBytes]byte
	generation int64
	mac        [sha256.Size]byte
}

// GenerateBootstrapCredential creates a credential from crypto/rand. The
// public value is canonical, unpadded base64url; its raw 32-byte value is never
// returned separately.
func GenerateBootstrapCredential() (BootstrapCredential, error) {
	return generateBootstrapCredential(rand.Reader)
}

func generateBootstrapCredential(random io.Reader) (BootstrapCredential, error) {
	var secret [BootstrapCredentialBytes]byte
	if _, err := io.ReadFull(random, secret[:]); err != nil {
		return BootstrapCredential{}, err
	}
	public := base64.RawURLEncoding.EncodeToString(secret[:])
	return BootstrapCredential{
		Public: public,
		SHA256: sha256.Sum256(secret[:]),
	}, nil
}

// ParseSessionCredential strictly parses the public routing portion of an s1
// session credential. Authentication still requires Store.Authenticate.
func ParseSessionCredential(credential string) (ParsedSessionCredential, error) {
	parsed, ok := parseSessionCredential(credential)
	if !ok {
		return ParsedSessionCredential{}, ErrUnauthorized
	}
	return parsed.public, nil
}

func parseSessionCredential(credential string) (parsedSessionCredential, bool) {
	if len(credential) < 6 || len(credential) > 160 {
		return parsedSessionCredential{}, false
	}
	parts := strings.Split(credential, ".")
	if len(parts) != 4 || parts[0] != sessionCredentialVersion {
		return parsedSessionCredential{}, false
	}

	sessionIDBytes, ok := decodeCanonicalRawURL(parts[1], SessionIDBytes)
	if !ok {
		return parsedSessionCredential{}, false
	}
	if len(parts[2]) == 0 || len(parts[2]) > 19 ||
		parts[2][0] < '1' || parts[2][0] > '9' {
		return parsedSessionCredential{}, false
	}
	for index := 1; index < len(parts[2]); index++ {
		if parts[2][index] < '0' || parts[2][index] > '9' {
			return parsedSessionCredential{}, false
		}
	}
	generation, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || generation < 1 ||
		strconv.FormatInt(generation, 10) != parts[2] {
		return parsedSessionCredential{}, false
	}
	macBytes, ok := decodeCanonicalRawURL(parts[3], sha256.Size)
	if !ok {
		return parsedSessionCredential{}, false
	}

	var parsed parsedSessionCredential
	copy(parsed.sessionID[:], sessionIDBytes)
	copy(parsed.mac[:], macBytes)
	parsed.generation = generation
	parsed.public = ParsedSessionCredential{
		SessionID:  parts[1],
		Generation: generation,
	}
	return parsed, true
}

func decodeCanonicalRawURL(value string, size int) ([]byte, bool) {
	if len(value) != base64.RawURLEncoding.EncodedLen(size) {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != size {
		return nil, false
	}
	if base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, false
	}
	return decoded, true
}

func bootstrapDigestForVerification(public string) ([sha256.Size]byte, bool) {
	decoded, valid := decodeCanonicalRawURL(public, BootstrapCredentialBytes)
	if !valid {
		// Still perform a fixed-size digest for malformed credentials so the
		// caller follows the same constant-time comparison path.
		return invalidBootstrapDigest, false
	}
	return sha256.Sum256(decoded), true
}

func encodeSessionCredential(
	key [sha256.Size]byte,
	sessionID [SessionIDBytes]byte,
	generation int64,
	listenerID string,
	agentID string,
	payloadBuildID string,
) string {
	mac := sessionMAC(
		key,
		sessionID,
		generation,
		listenerID,
		agentID,
		payloadBuildID,
	)
	return strings.Join([]string{
		sessionCredentialVersion,
		base64.RawURLEncoding.EncodeToString(sessionID[:]),
		strconv.FormatInt(generation, 10),
		base64.RawURLEncoding.EncodeToString(mac[:]),
	}, ".")
}

func sessionMAC(
	key [sha256.Size]byte,
	sessionID [SessionIDBytes]byte,
	generation int64,
	listenerID string,
	agentID string,
	payloadBuildID string,
) [sha256.Size]byte {
	mac := hmac.New(sha256.New, key[:])
	writeMACField(mac, []byte(sessionMACDomain))
	writeMACField(mac, sessionID[:])
	var generationBytes [8]byte
	binary.BigEndian.PutUint64(generationBytes[:], uint64(generation))
	writeMACField(mac, generationBytes[:])
	writeMACField(mac, []byte(listenerID))
	writeMACField(mac, []byte(agentID))
	writeMACField(mac, []byte(payloadBuildID))

	var result [sha256.Size]byte
	copy(result[:], mac.Sum(nil))
	return result
}

type hashWriter interface {
	Write([]byte) (int, error)
}

func writeMACField(writer hashWriter, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = writer.Write(size[:])
	_, _ = writer.Write(value)
}

func constantBytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		// Compare fixed digests even for malformed durable data.
		leftDigest := sha256.Sum256(left)
		rightDigest := sha256.Sum256(right)
		return subtle.ConstantTimeCompare(leftDigest[:], rightDigest[:]) == 1 &&
			len(left) == len(right)
	}
	return subtle.ConstantTimeCompare(left, right) == 1
}

func constantStringEqual(left, right string) bool {
	leftDigest := sha256.Sum256([]byte(left))
	rightDigest := sha256.Sum256([]byte(right))
	return subtle.ConstantTimeCompare(leftDigest[:], rightDigest[:]) == 1
}
