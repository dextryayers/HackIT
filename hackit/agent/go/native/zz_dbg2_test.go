package native

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDbgSSTI2(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		var x, y int
		if _, err := fmt.Sscanf(name, "{{%d*%d}}", &x, &y); err == nil {
			fmt.Fprintf(w, "Hello %d", x*y)
			return
		}
		w.Write([]byte("Hello " + name))
	}))
	defer srv.Close()
	for _, r := range TestSSTI(srv.URL+"/g?name=x", map[string]string{"name": "x"}) {
		t.Logf("vuln=%v payload=%q ev=%s", r.Vulnerable, r.Payload, r.Evidence)
	}
}
