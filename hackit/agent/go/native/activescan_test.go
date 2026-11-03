package native

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// vulnMux reproduces the detector-relevant behaviours of a deliberately
// vulnerable app without needing an external process.
func vulnMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/user", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("id"), "'") {
			w.WriteHeader(500)
			w.Write([]byte("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"))
			return
		}
		w.Write([]byte(`{"rows":[{"id":1}]}`))
	})
	mux.HandleFunc("/api/greet", func(w http.ResponseWriter, r *http.Request) {
		// Minimal template evaluator: resolves {{A*B}} like a real engine would.
		name := r.URL.Query().Get("name")
		var x, y int
		if _, err := fmt.Sscanf(name, "{{%d*%d}}", &x, &y); err == nil {
			fmt.Fprintf(w, "Hello %d", x*y)
			return
		}
		w.Write([]byte("Hello " + name))
	})
	mux.HandleFunc("/api/file", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("path"), "etc/passwd") {
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
			return
		}
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/api/cors", func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Write([]byte(`{"ok":true}`))
	})
	// Benign page that happens to contain numbers and words the detectors
	// previously treated as proof.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=()")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Write([]byte("<html><body>49 status up localhost 127.0.0.1 windows</body></html>"))
	})
	return mux
}

func idsFor(t *testing.T, base string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, f := range ActiveScan([]string{base}, nil, nil) {
		out[f.ID] = f.Evidence
	}
	return out
}

func TestActiveScanDetectsRealIssues(t *testing.T) {
	srv := httptest.NewServer(vulnMux())
	defer srv.Close()

	cases := []struct{ path, id string }{
		{"/api/user?id=1", "INJ-SQLI"},
		{"/api/greet?name=x", "INJ-SSTI"},
		{"/api/file?path=index", "INJ-LFI"},
		{"/api/cors", "MISCONF-CORS"},
	}
	for _, c := range cases {
		got := idsFor(t, srv.URL+c.path)
		if _, ok := got[c.id]; !ok {
			t.Errorf("%s not detected on %s", c.id, c.path)
		}
	}
}

func TestActiveScanRejectsBenignPage(t *testing.T) {
	srv := httptest.NewServer(vulnMux())
	defer srv.Close()

	got := idsFor(t, srv.URL)
	for _, id := range []string{"INJ-SQLI", "INJ-SSTI", "INJ-LFI", "INJ-CMD", "MISCONF-CORS", "MISCONF-CSRF", "MISCONF-HEADERS"} {
		if ev, ok := got[id]; ok {
			t.Errorf("false positive %s on benign page: %s", id, ev)
		}
	}
}
