package profiles

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/rivo/uniseg"
	"golang.org/x/text/unicode/norm"
)

const (
	maxDisplayNameGraphemes = 64
	maxDisplayNameBytes     = 512
	maxAboutGraphemes       = 280
	maxAboutBytes           = 2048
)

var ErrInvalidProfileText = errors.New("invalid profile text")

func NormalizeProfileText(displayName *string, about string) (*string, string, error) {
	normalizedAbout, err := normalizeField(about, true, maxAboutGraphemes, maxAboutBytes)
	if err != nil {
		return nil, "", err
	}

	var normalizedDisplayName *string
	if displayName != nil {
		value, normalizeErr := normalizeField(*displayName, false, maxDisplayNameGraphemes, maxDisplayNameBytes)
		if normalizeErr != nil {
			return nil, "", normalizeErr
		}
		if value != "" {
			normalizedDisplayName = &value
		}
	}

	return normalizedDisplayName, normalizedAbout, nil
}

func normalizeField(value string, allowLF bool, maxGraphemes, maxBytes int) (string, error) {
	if !utf8.ValidString(value) {
		return "", ErrInvalidProfileText
	}
	value = norm.NFC.String(strings.TrimSpace(value))
	if len(value) > maxBytes || uniseg.GraphemeClusterCount(value) > maxGraphemes {
		return "", ErrInvalidProfileText
	}
	for _, r := range value {
		if r == '\n' && allowLF {
			continue
		}
		if unicode.IsControl(r) || isDirectionalControl(r) {
			return "", ErrInvalidProfileText
		}
	}
	return value, nil
}

func isDirectionalControl(r rune) bool {
	switch r {
	case '\u061c', '\u200e', '\u200f',
		'\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
		'\u2066', '\u2067', '\u2068', '\u2069',
		'\u206a', '\u206b', '\u206c', '\u206d', '\u206e', '\u206f':
		return true
	default:
		return false
	}
}
