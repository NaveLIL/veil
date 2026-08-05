package nodeorigin

import "testing"

func FuzzCanonicalOriginRoundTrip(f *testing.F) {
	for _, seed := range []string{
		"https://veil.example:443",
		"http://127.0.0.1:8080",
		"http://[::1]:8080",
		"https://EXAMPLE.com:443",
		"https://example.com:0443",
		"https://example.com:443/path",
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		validationErr := ValidateCanonical(value)
		parsed, parseErr := ParseCanonical(value)
		if (validationErr == nil) != (parseErr == nil) {
			t.Fatalf("validator/parser disagreement for %q: validate=%v parse=%v", value, validationErr, parseErr)
		}
		if parseErr != nil {
			if !parsed.IsZero() {
				t.Fatal("rejected origin produced a non-zero parsed value")
			}
			return
		}
		if parsed.IsZero() || parsed.String() != value {
			t.Fatalf("canonical origin did not preserve exact bytes: %q -> %q", value, parsed.String())
		}
		if err := ValidateCanonical(parsed.String()); err != nil {
			t.Fatalf("accepted origin did not revalidate: %v", err)
		}
	})
}
