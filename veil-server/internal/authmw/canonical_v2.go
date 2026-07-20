package authmw

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/NaveLIL/veil/veil-server/internal/nodeorigin"
	"github.com/google/uuid"
)

const (
	// RESTAuthV2Domain separates the binary REST v2 signing transcript from
	// every legacy, WebSocket, and application-level signature domain.
	RESTAuthV2Domain = "veil-rest-auth-v2\x00"

	RESTAuthV2NonceSize      = 32
	RESTAuthV2MaxOriginBytes = nodeorigin.MaxBytes
	RESTAuthV2MaxMethodBytes = 32
	RESTAuthV2MaxTargetBytes = 16 * 1024
)

// RESTAuthV2Input is the transport-neutral input to the non-activated REST v2
// signing contract. CanonicalOrigin must come from trusted Node configuration,
// never from the request Host header.
type RESTAuthV2Input struct {
	CanonicalOrigin string
	UserID          string
	Method          string
	RequestTarget   string
	TimestampMS     uint64
	Nonce           [RESTAuthV2NonceSize]byte
	BodySHA256      [sha256.Size]byte
}

// RESTAuthV2BodyDigest returns the exact fixed-width digest carried by the
// REST v2 signing transcript.
func RESTAuthV2BodyDigest(body []byte) [sha256.Size]byte {
	return sha256.Sum256(body)
}

// RESTAuthV2SigningMessage returns the exact binary preimage:
//
//	domain || u32be(origin_len) || origin || user_uuid_16 ||
//	u32be(method_len) || method || u32be(target_len) || target ||
//	u64be(timestamp_ms) || nonce_32 || sha256(body)_32
//
// Lengths count bytes, not characters. All textual fields are validated as
// canonical ASCII before they are appended.
func RESTAuthV2SigningMessage(input RESTAuthV2Input) ([]byte, error) {
	if err := ValidateCanonicalRESTOriginV2(input.CanonicalOrigin); err != nil {
		return nil, err
	}
	userID, err := ParseCanonicalRESTUserIDV2(input.UserID)
	if err != nil {
		return nil, err
	}
	if err := ValidateCanonicalRESTMethodV2(input.Method); err != nil {
		return nil, err
	}
	if err := ValidateCanonicalRESTTargetV2(input.RequestTarget); err != nil {
		return nil, err
	}
	if input.TimestampMS == 0 || input.TimestampMS > math.MaxInt64 {
		return nil, errors.New("REST auth v2 timestamp is out of range")
	}
	if allZeroRESTAuthV2(input.Nonce[:]) {
		return nil, errors.New("REST auth v2 nonce must not be zero")
	}

	capacity := len(RESTAuthV2Domain) + 4 + len(input.CanonicalOrigin) + len(userID) +
		4 + len(input.Method) + 4 + len(input.RequestTarget) + 8 +
		RESTAuthV2NonceSize + sha256.Size
	message := make([]byte, 0, capacity)
	message = append(message, RESTAuthV2Domain...)
	message = appendRESTAuthV2LengthPrefixed(message, input.CanonicalOrigin)
	message = append(message, userID[:]...)
	message = appendRESTAuthV2LengthPrefixed(message, input.Method)
	message = appendRESTAuthV2LengthPrefixed(message, input.RequestTarget)
	var integer [8]byte
	binary.BigEndian.PutUint64(integer[:], input.TimestampMS)
	message = append(message, integer[:]...)
	message = append(message, input.Nonce[:]...)
	message = append(message, input.BodySHA256[:]...)
	return message, nil
}

func appendRESTAuthV2LengthPrefixed(output []byte, value string) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	output = append(output, length[:]...)
	return append(output, value...)
}

// ParseCanonicalRESTUserIDV2 accepts only a lowercase, hyphenated, non-nil
// UUID and returns its RFC/network-order 16-byte representation.
func ParseCanonicalRESTUserIDV2(value string) ([16]byte, error) {
	var output [16]byte
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil || len(value) != 36 || parsed.String() != value {
		return output, errors.New("REST auth v2 user id is not canonical")
	}
	copy(output[:], parsed[:])
	return output, nil
}

// ParseCanonicalRESTTimestampV2 accepts the canonical unsigned decimal header
// form and rejects signs, leading zeroes, zero, and values outside int64.
func ParseCanonicalRESTTimestampV2(value string) (uint64, error) {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return 0, errors.New("REST auth v2 timestamp is not canonical")
	}
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return 0, errors.New("REST auth v2 timestamp is not canonical")
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed == 0 || parsed > math.MaxInt64 || strconv.FormatUint(parsed, 10) != value {
		return 0, errors.New("REST auth v2 timestamp is out of range")
	}
	return parsed, nil
}

// ParseCanonicalRESTNonceV2 accepts exactly one unpadded base64url encoding of
// a non-zero 32-byte nonce. Re-encoding equality eliminates textual aliases.
func ParseCanonicalRESTNonceV2(value string) ([RESTAuthV2NonceSize]byte, error) {
	var output [RESTAuthV2NonceSize]byte
	if len(value) != base64.RawURLEncoding.EncodedLen(RESTAuthV2NonceSize) {
		return output, errors.New("REST auth v2 nonce has invalid length")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != RESTAuthV2NonceSize ||
		base64.RawURLEncoding.EncodeToString(decoded) != value {
		return output, errors.New("REST auth v2 nonce is not canonical base64url")
	}
	copy(output[:], decoded)
	if allZeroRESTAuthV2(output[:]) {
		return [RESTAuthV2NonceSize]byte{}, errors.New("REST auth v2 nonce must not be zero")
	}
	return output, nil
}

// ValidateCanonicalRESTOriginV2 requires a complete, already-canonical origin
// with an explicit port. HTTPS is mandatory except for exact local-loopback
// HTTP development origins.
func ValidateCanonicalRESTOriginV2(origin string) error {
	if err := nodeorigin.ValidateCanonical(origin); err != nil {
		return fmt.Errorf("REST auth v2 origin is invalid: %w", err)
	}
	return nil
}

// ValidateCanonicalRESTMethodV2 accepts a bounded uppercase HTTP token.
func ValidateCanonicalRESTMethodV2(method string) error {
	if method == "" || len(method) > RESTAuthV2MaxMethodBytes {
		return errors.New("REST auth v2 method is empty or oversized")
	}
	for index := 0; index < len(method); index++ {
		character := method[index]
		if (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			strings.ContainsRune("!#$%&'*+-.^_`|~", rune(character)) {
			continue
		}
		return errors.New("REST auth v2 method is not an uppercase HTTP token")
	}
	return nil
}

// ValidateCanonicalRESTTargetV2 accepts one exact ASCII origin-form request
// target. It preserves query order and escaping, but rejects URI aliases that
// intermediaries commonly normalize differently.
func ValidateCanonicalRESTTargetV2(target string) error {
	if target == "" || len(target) > RESTAuthV2MaxTargetBytes || target[0] != '/' {
		return errors.New("REST auth v2 request target is not bounded origin-form")
	}
	firstQuery := strings.IndexByte(target, '?')
	if firstQuery == len(target)-1 {
		return errors.New("REST auth v2 request target has an empty query alias")
	}
	inQuery := false
	for index := 0; index < len(target); index++ {
		character := target[index]
		if character < 0x21 || character > 0x7e || character == '#' || character == '\\' {
			return errors.New("REST auth v2 request target contains a forbidden byte")
		}
		if character == '?' {
			inQuery = true
			continue
		}
		if character == '%' {
			if index+2 >= len(target) || !upperHexRESTAuthV2(target[index+1]) ||
				!upperHexRESTAuthV2(target[index+2]) {
				return errors.New("REST auth v2 request target has a non-canonical escape")
			}
			decoded := decodeUpperHexRESTAuthV2(target[index+1], target[index+2])
			if unreservedRESTAuthV2(decoded) || decoded == '\\' || (!inQuery && decoded == '/') {
				return errors.New("REST auth v2 request target has an aliased escape")
			}
			index += 2
			continue
		}
		if unreservedRESTAuthV2(character) || character == '/' ||
			strings.ContainsRune("!$&'()*+,;=:@", rune(character)) ||
			(inQuery && character == '?') {
			continue
		}
		return errors.New("REST auth v2 request target is not canonical URI ASCII")
	}

	path := target
	if firstQuery >= 0 {
		path = path[:firstQuery]
	}
	if strings.Contains(path, "//") {
		return errors.New("REST auth v2 request target has a duplicate-slash alias")
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return errors.New("REST auth v2 request target has a dot-segment alias")
		}
	}
	return nil
}

func upperHexRESTAuthV2(value byte) bool {
	return (value >= '0' && value <= '9') || (value >= 'A' && value <= 'F')
}

func decodeUpperHexRESTAuthV2(high, low byte) byte {
	decode := func(value byte) byte {
		if value <= '9' {
			return value - '0'
		}
		return value - 'A' + 10
	}
	return decode(high)<<4 | decode(low)
}

func unreservedRESTAuthV2(value byte) bool {
	return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') ||
		(value >= '0' && value <= '9') || strings.ContainsRune("-._~", rune(value))
}

func allZeroRESTAuthV2(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
