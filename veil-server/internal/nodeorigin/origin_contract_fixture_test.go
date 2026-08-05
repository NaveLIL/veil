package nodeorigin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const (
	originCorpusReviewedSHA256 = "42b8fe154439b3dde57a1c3e9c3f845c7a9df04649e6fd85b28ec577fff0ef5c"
	originCorpusMaxBytes       = 64 * 1024
	originCorpusMaxRows        = 256
	originCorpusSyntheticNote  = "Synthetic cross-runtime canonical Node origin grammar only; contains no credentials or production secrets."
)

type originCorpusV1 struct {
	SchemaVersion uint32   `json:"schema_version"`
	SyntheticOnly bool     `json:"synthetic_only"`
	Note          string   `json:"note"`
	Accepted      []string `json:"accepted"`
	Rejected      []string `json:"rejected"`
}

func TestSharedOriginV1CorpusMatchesGoValidator(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve origin corpus test source path")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
	corpusPath := filepath.Join(repositoryRoot, "test-vectors", "transport-auth", "origin-v1.json")
	corpusBytes := readBoundedOriginCorpus(t, corpusPath)
	if bytes.ContainsRune(corpusBytes, '\r') || !bytes.HasSuffix(corpusBytes, []byte("\n")) ||
		bytes.HasSuffix(corpusBytes, []byte("\n\n")) {
		t.Fatal("origin corpus must be LF-only with exactly one final LF")
	}
	digest := sha256.Sum256(corpusBytes)
	if got := hex.EncodeToString(digest[:]); got != originCorpusReviewedSHA256 {
		t.Fatalf("origin corpus SHA-256 = %s, want reviewed %s", got, originCorpusReviewedSHA256)
	}

	decoder := json.NewDecoder(bytes.NewReader(corpusBytes))
	decoder.DisallowUnknownFields()
	var corpus originCorpusV1
	if err := decoder.Decode(&corpus); err != nil {
		t.Fatalf("decode strict origin corpus: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("origin corpus contains trailing JSON data: %v", err)
	}
	if corpus.SchemaVersion != 1 || !corpus.SyntheticOnly || corpus.Note != originCorpusSyntheticNote {
		t.Fatal("origin corpus metadata is not the reviewed synthetic schema")
	}
	if len(corpus.Accepted) == 0 || len(corpus.Rejected) == 0 ||
		len(corpus.Accepted) > originCorpusMaxRows || len(corpus.Rejected) > originCorpusMaxRows {
		t.Fatal("origin corpus row count is invalid")
	}

	seen := make(map[string]struct{}, len(corpus.Accepted)+len(corpus.Rejected))
	for _, origin := range corpus.Accepted {
		if _, duplicate := seen[origin]; duplicate {
			t.Fatalf("duplicate origin corpus row %q", origin)
		}
		seen[origin] = struct{}{}
		parsed, err := ParseCanonical(origin)
		if err != nil {
			t.Fatalf("accepted origin %q failed: %v", origin, err)
		}
		if parsed.String() != origin {
			t.Fatalf("accepted origin normalized from %q to %q", origin, parsed.String())
		}
	}
	for _, origin := range corpus.Rejected {
		if _, duplicate := seen[origin]; duplicate {
			t.Fatalf("duplicate origin corpus row %q", origin)
		}
		seen[origin] = struct{}{}
		if _, err := ParseCanonical(origin); err == nil {
			t.Fatalf("rejected origin %q was accepted", origin)
		}
	}
}

func readBoundedOriginCorpus(t *testing.T, path string) []byte {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > originCorpusMaxBytes {
		t.Fatalf("origin corpus is not a bounded regular file: mode=%v size=%d", info.Mode(), info.Size())
	}
	contents, err := io.ReadAll(io.LimitReader(file, originCorpusMaxBytes+1))
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(contents)) != info.Size() {
		t.Fatalf("origin corpus changed size while reading: stat=%d read=%d", info.Size(), len(contents))
	}
	return contents
}
