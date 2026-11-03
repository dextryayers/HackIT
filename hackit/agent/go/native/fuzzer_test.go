package native

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// hiddenMux serves high-signal files plus a catch-all page that contains
// words ("query", "status up") that the old detectors treated as evidence.
func hiddenMux() *http.ServeMux {
	mux := http.NewServeMux()
	files := map[string]string{
		"/.aws/credentials":   "[default]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = secret\n",
		"/.ssh/id_rsa":        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n",
		"/.htaccess":          "RewriteEngine On\nRewriteCond %{REQUEST_FILENAME} !-f\n",
		"/Dockerfile":         "FROM node:20-alpine\nRUN npm ci --omit=dev\nCOPY . /app\n",
		"/docker-compose.yml": "services:\n  web:\n    image: nginx:1.25\n",
		"/web.config":         "<configuration>\n  <system.web><compilation debug=\"true\"/></system.web>\n</configuration>\n",
	}
	for path, body := range files {
		body := body
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(body))
		})
	}
	mux.HandleFunc("/.DS_Store", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("\x00\x00\x00\x01Bud1\x00\x00\x10\x00\x00\x00\x08\x00\x00\x00\x00"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>graphql query status up</body></html>"))
	})
	return mux
}

func TestFuzzDetectsHiddenFiles(t *testing.T) {
	srv := httptest.NewServer(hiddenMux())
	defer srv.Close()

	found := map[string]string{}
	for _, res := range FuzzDirectories(srv.URL, 4) {
		found[res.Path] = res.Evidence
	}
	for _, path := range []string{
		"/.aws/credentials", "/.ssh/id_rsa", "/.DS_Store",
		"/.htaccess", "/Dockerfile", "/docker-compose.yml", "/web.config",
	} {
		if found[path] == "" {
			t.Errorf("%s not detected as verified; got %v", path, found)
		}
	}
}

func TestFuzzRejectsCatchAllPage(t *testing.T) {
	srv := httptest.NewServer(hiddenMux())
	defer srv.Close()

	found := map[string]string{}
	for _, res := range FuzzDirectories(srv.URL, 4) {
		found[res.Path] = res.Evidence
	}
	// The catch-all body answers every path with HTML; nothing else may pass.
	for path := range found {
		ok := map[string]bool{
			"/.aws/credentials": true, "/.ssh/id_rsa": true, "/.DS_Store": true,
			"/.htaccess": true, "/Dockerfile": true, "/docker-compose.yml": true,
			"/web.config": true,
		}[path]
		if !ok {
			t.Errorf("false positive on catch-all server: %s (%s)", path, found[path])
		}
	}
}

func TestVerifyUsesSameSignaturesAsFuzzer(t *testing.T) {
	srv := httptest.NewServer(hiddenMux())
	defer srv.Close()

	cases := map[string]string{
		"/.aws/credentials":   "MISCONF-AWS-CREDS",
		"/.ssh/id_rsa":        "MISCONF-SSH-KEY",
		"/.DS_Store":          "MISCONF-DSSTORE",
		"/.htaccess":          "MISCONF-HTACCESS",
		"/Dockerfile":         "MISCONF-DOCKERFILE",
		"/docker-compose.yml": "MISCONF-COMPOSE",
		"/web.config":         "MISCONF-WEBCONFIG",
	}
	for path, wantID := range cases {
		f := VerifyExposedEndpoint(srv.URL + path)
		if f == nil || f.ID != wantID {
			t.Errorf("%s: want %s, got %+v", path, wantID, f)
		}
	}
}

// Every rule is rendered with two arguments; a template missing a verb
// produces "%!(EXTRA int=200)" in the report, which this guards against.
func TestEndpointRuleTemplatesRenderCleanly(t *testing.T) {
	for kind, rule := range endpointRules {
		out := fmt.Sprintf(rule.description, "http://h/p", 200)
		if strings.Contains(out, "%!") {
			t.Errorf("%s template is malformed: %q", kind, out)
		}
	}
}

func TestVerifyHiddenFileRejectsSoft404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>welcome — query status up</html>"))
	}))
	defer srv.Close()

	for _, path := range []string{"/.ssh/id_rsa", "/.aws/credentials", "/graphql"} {
		if f := VerifyExposedEndpoint(srv.URL + path); f != nil {
			t.Errorf("soft-404 must not confirm %s, got %+v", path, f)
		}
	}
}

func TestEnvWithoutSecretsIsNotCritical(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.Write([]byte("APP_ENV=production\nAPP_DEBUG=false\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	// The file is still worth enumerating, but it holds no credentials, so it
	// must not become a Critical 9.8 finding.
	if f := VerifyExposedEndpoint(srv.URL + "/.env"); f != nil {
		t.Fatalf("credential-free .env must not be a Critical finding, got %+v", f)
	}
}

func TestVerifyWordPressBackupConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wp-config.php.bak" {
			w.Write([]byte("<?php\ndefine('DB_NAME', 'wp');\ndefine('DB_USER', 'root');\ndefine('DB_PASSWORD', 'hunter2');\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	f := VerifyExposedEndpoint(srv.URL + "/wp-config.php.bak")
	if f == nil || f.ID != "MISCONF-WPCONFIG" || f.Severity != "Critical" {
		t.Fatalf("wp-config backup with DB creds must be Critical, got %+v", f)
	}
}

func TestVerifyGraphQLRequiresResolver(t *testing.T) {
	// Page mentions GraphQL but does not resolve {__typename}.
	soft := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>graphql query</html>`))
	}))
	defer soft.Close()
	if f := VerifyExposedEndpoint(soft.URL + "/graphql"); f != nil {
		t.Fatalf("text mentioning graphql must not confirm, got %+v", f)
	}

	// Real endpoint answers the typed query.
	real := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.Contains(r.Header.Get("Content-Type"), "json") {
			w.Write([]byte(`{"errors":[{"message":"expected POST"}]}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{"__typename":"Query"}}`))
	}))
	defer real.Close()
	f := VerifyExposedEndpoint(real.URL + "/graphql")
	if f == nil || f.ID != "MISCONF-GRAPHQL" {
		t.Fatalf("resolving endpoint must confirm, got %+v", f)
	}
}
