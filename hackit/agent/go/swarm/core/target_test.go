package core

import "testing"

func TestParseTargetKinds(t *testing.T) {
	cases := []struct {
		in     string
		host   string
		kind   TargetKind
		priv   bool
		port   string
		scheme string
	}{
		{"https://tesla.com", "tesla.com", TargetDomain, false, "", "https"},
		{"https://tesla.com/some/path?q=1", "tesla.com", TargetDomain, false, "", "https"},
		{"example.com:8443", "example.com", TargetDomain, false, "8443", ""},
		{"1.2.3.4", "1.2.3.4", TargetIPv4, false, "", ""},
		{"127.0.0.1", "127.0.0.1", TargetLocal, true, "", ""},
		{"192.168.1.10", "192.168.1.10", TargetLocal, true, "", ""},
		{"::1", "::1", TargetLocal, true, "", ""},
		{"[2001:db8::1]:8080", "2001:db8::1", TargetIPv6, false, "8080", ""},
		{"localhost", "localhost", TargetLocal, true, "", ""},
		{"10.0.0.0/30", "10.0.0.0/30", TargetCIDR, true, "", ""},
		{"http://internal.lan:8080/admin", "internal.lan", TargetLocal, true, "8080", "http"},
		{"*.example.com", "example.com", TargetDomain, false, "", ""},
	}
	for _, tc := range cases {
		got := ParseTarget(tc.in)
		if got.Host != tc.host {
			t.Errorf("%q: host = %q, want %q", tc.in, got.Host, tc.host)
		}
		if got.Kind != tc.kind {
			t.Errorf("%q: kind = %q, want %q", tc.in, got.Kind, tc.kind)
		}
		if got.IsPrivate != tc.priv {
			t.Errorf("%q: private = %v, want %v", tc.in, got.IsPrivate, tc.priv)
		}
		if got.Port != tc.port {
			t.Errorf("%q: port = %q, want %q", tc.in, got.Port, tc.port)
		}
		if tc.scheme != "" && got.Scheme != tc.scheme {
			t.Errorf("%q: scheme = %q, want %q", tc.in, got.Scheme, tc.scheme)
		}
	}
}

func TestParseTargetEmpty(t *testing.T) {
	if got := ParseTarget(""); got.Kind != TargetUnknown || got.Host != "" {
		t.Fatalf("empty input should be unknown, got %+v", got)
	}
}

func TestCIDRSeeds(t *testing.T) {
	got := ParseTarget("10.0.0.0/30")
	if len(got.ScanSeeds) != 4 {
		t.Fatalf("/30 should yield 4 seeds, got %d: %v", len(got.ScanSeeds), got.ScanSeeds)
	}
	big := ParseTarget("10.0.0.0/8")
	if len(big.ScanSeeds) == 0 || len(big.ScanSeeds) > 256 {
		t.Fatalf("/8 seeds must be capped at 256, got %d", len(big.ScanSeeds))
	}
}
