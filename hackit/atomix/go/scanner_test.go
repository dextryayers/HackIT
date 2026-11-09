package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveTemplateVars(t *testing.T) {
	v := NewTemplateVars("https://example.com:8443/path?q=1")
	out := v.Resolve("{{BaseURL}}|{{Hostname}}|{{Port}}|{{Scheme}}")
	if out != "https://example.com:8443/path?q=1|example.com|8443|https" {
		t.Fatalf("Resolve got %q", out)
	}
	def := NewTemplateVars("https://example.com/")
	if out := def.Resolve("{{Port}}"); out != "443" {
		t.Fatalf("default https port: got %q", out)
	}
	http := NewTemplateVars("http://example.com/")
	if out := http.Resolve("{{Port}}"); out != "80" {
		t.Fatalf("default http port: got %q", out)
	}
}

func TestResolvePayload(t *testing.T) {
	v := NewTemplateVars("https://example.com")
	out := ResolvePayload("{{BaseURL}}/x?a={{url_encode}}", "a b&c", v)
	if !strings.Contains(out, "a+b%26c") && !strings.Contains(out, "a%20b%26c") {
		t.Fatalf("url_encode got %q", out)
	}
	b64 := ResolvePayload("{{base64}}", "hello", v)
	if b64 != "aGVsbG8=" {
		t.Fatalf("base64 got %q", b64)
	}
}

func TestRandomStringAndInt(t *testing.T) {
	a, b := randomString(16), randomString(16)
	if a == b {
		t.Fatal("randomString collision on 16 bytes")
	}
	if len(a) != 16 {
		t.Fatalf("randomString length %d", len(a))
	}
	for i := 0; i < 100; i++ {
		n := randomInt(10, 20)
		if n < 10 || n > 20 {
			t.Fatalf("randomInt out of range: %d", n)
		}
	}
}

func TestResumeTrackerRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resume.log")
	tracker, err := NewResumeTracker(path)
	if err != nil {
		t.Fatal(err)
	}
	if tracker.Done("https://a.example.com", "tpl-1") {
		t.Fatal("fresh tracker must not report done")
	}
	tracker.Mark("https://a.example.com", "tpl-1")
	tracker.Close()

	tracker2, err := NewResumeTracker(path)
	if err != nil {
		t.Fatal(err)
	}
	defer tracker2.Close()
	if !tracker2.Done("https://a.example.com", "tpl-1") {
		t.Fatal("reloaded tracker must report done for marked pair")
	}
	if tracker2.Done("https://a.example.com", "tpl-2") {
		t.Fatal("reloaded tracker must not report unmarked pair")
	}
}

func TestDeduplicator(t *testing.T) {
	d := NewDeduplicator()
	if d.IsDuplicate("t", "u", "m") {
		t.Fatal("fresh deduplicator must not report duplicates")
	}
	d.MarkSeen("t", "u", "m")
	if !d.IsDuplicate("t", "u", "m") {
		t.Fatal("marked key must be a duplicate")
	}
	if d.IsDuplicate("t", "u", "m2") {
		t.Fatal("different matcher must not be a duplicate")
	}
}
