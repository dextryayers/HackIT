package native

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVerifyExposedEnvConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.Write([]byte("APP_ENV=production\nDB_PASSWORD=hunter2\nSECRET_KEY=abc\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	f := VerifyExposedEndpoint(srv.URL + "/.env")
	if f == nil {
		t.Fatal(".env with secrets must be confirmed")
	}
	if f.Severity != "Critical" || f.ID != "MISCONF-001" {
		t.Fatalf("unexpected finding: %+v", f)
	}
}

func TestVerifyExposedEnvSoft404Rejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>welcome to the app</html>"))
	}))
	defer srv.Close()

	if f := VerifyExposedEndpoint(srv.URL + "/.env"); f != nil {
		t.Fatalf("soft-404 must not be confirmed, got %+v", f)
	}
}

func TestVerifyGitConfigConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.git/config" {
			w.Write([]byte("[core]\n\trepositoryformatversion = 0\n\tbare = false\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	f := VerifyExposedEndpoint(srv.URL + "/.git/config")
	if f == nil || f.ID != "MISCONF-002" {
		t.Fatalf(".git/config with [core] must be confirmed, got %+v", f)
	}
}

func TestVerifyServiceBannerPinnedCVE(t *testing.T) {
	f := VerifyServiceBanner("10.0.0.1", 80, "Apache/2.4.49 (Unix)", "apache")
	if f == nil || f.ID != "CVE-2021-41773" || f.Severity != "Critical" {
		t.Fatalf("Apache 2.4.49 must match CVE-2021-41773, got %+v", f)
	}
	// Modern Apache carries no version-specific claim.
	if f := VerifyServiceBanner("10.0.0.1", 80, "Apache/2.4.62 (Unix)", "apache"); f != nil {
		t.Fatalf("modern Apache must not produce a CVE claim, got %+v", f)
	}
	// Unknown banner must never invent a finding.
	if f := VerifyServiceBanner("10.0.0.1", 5000, "", "unknown"); f != nil {
		t.Fatalf("empty banner must not produce a finding, got %+v", f)
	}
}

func TestValidateApacheTraversalConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "etc/passwd") || strings.Contains(r.URL.EscapedPath(), "%2e") {
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	p := ValidateApacheTraversal(srv.URL)
	if p == nil || !p.Success {
		t.Fatalf("traversal serving passwd must be confirmed, got %+v", p)
	}
	if !strings.Contains(p.Evidence, "root:x") {
		t.Fatalf("evidence must quote passwd content: %q", p.Evidence)
	}
}

func TestValidateApacheTraversalClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	p := ValidateApacheTraversal(srv.URL)
	if p == nil || p.Success {
		t.Fatalf("clean server must report closed door, got %+v", p)
	}
}
