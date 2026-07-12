package profiles

import (
	"strings"
	"testing"

	"golang.org/x/text/unicode/norm"
)

func TestNormalizeProfileTextNormalizesNFCAndEmptyDisplayName(t *testing.T) {
	displayName := "  \t  "
	normalizedDisplayName, about, err := NormalizeProfileText(&displayName, "  Cafe\u0301  ")
	if err != nil {
		t.Fatal(err)
	}
	if normalizedDisplayName != nil {
		t.Fatalf("display name = %q, want nil", *normalizedDisplayName)
	}
	if about != "Café" || !norm.NFC.IsNormalString(about) {
		t.Fatalf("about = %q, want NFC Café", about)
	}
}

func TestNormalizeProfileTextAllowsEmojiGraphemesAndLF(t *testing.T) {
	displayName := strings.Repeat("👩‍💻", 32)
	got, about, err := NormalizeProfileText(&displayName, "line one\nline two")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || *got != displayName || about != "line one\nline two" {
		t.Fatalf("unexpected normalized values: %#v %q", got, about)
	}
}

func TestNormalizeProfileTextRejectsBoundsControlsAndBidi(t *testing.T) {
	tests := []struct {
		name        string
		displayName string
		about       string
	}{
		{name: "display graphemes", displayName: strings.Repeat("a", maxDisplayNameGraphemes+1)},
		{name: "about graphemes", displayName: "ok", about: strings.Repeat("a", maxAboutGraphemes+1)},
		{name: "display newline", displayName: "line\nbreak"},
		{name: "about tab", displayName: "ok", about: "tab\tvalue"},
		{name: "bidi override", displayName: "safe\u202eevil"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := NormalizeProfileText(&test.displayName, test.about); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}
