package native

import "testing"

func TestDbgSSTI(t *testing.T) {
	res := TestSSTI("http://127.0.0.1:19090/api/greet?name=x", map[string]string{"name": "x"})
	for _, r := range res {
		t.Logf("vuln=%v payload=%q ev=%s", r.Vulnerable, r.Payload, r.Evidence)
	}
}
