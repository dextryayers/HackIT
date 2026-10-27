package native

import "testing"

func TestNormalizeFuzzBase(t *testing.T) {
	cases := map[string]string{
		"http://127.0.0.1:18086/?id=1":       "http://127.0.0.1:18086/",
		"http://127.0.0.1:18086":             "http://127.0.0.1:18086/",
		"https://example.com/app":            "https://example.com/app/",
		"https://example.com/app?next=%2Fho": "https://example.com/app/",
		"https://example.com/app/#fragment":  "https://example.com/app/",
	}
	for input, expected := range cases {
		if actual := normalizeFuzzBase(input); actual != expected {
			t.Fatalf("normalizeFuzzBase(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func TestNormalizeSubdomain(t *testing.T) {
	cases := []struct {
		name     string
		domain   string
		expected string
	}{
		{"*.api.example.com", "example.com", "api.example.com"},
		{"https://app.example.com/login", "example.com", "app.example.com"},
		{"example.com", "example.com", ""},
		{"127.0.0.1", "example.com", ""},
		{"https://127.0.0.1", "127.0.0.1", ""},
		{"evil-example.com", "example.com", ""},
		{"not a hostname", "example.com", ""},
		{"API.Example.COM.", "example.com", "api.example.com"},
	}
	for _, test := range cases {
		if actual := normalizeSubdomain(test.name, test.domain); actual != test.expected {
			t.Fatalf("normalizeSubdomain(%q, %q) = %q, want %q",
				test.name, test.domain, actual, test.expected)
		}
	}
}

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		"https://Example.COM/path?q=1": "example.com",
		"*.example.com.":               "example.com",
		"example.com":                  "example.com",
	}
	for input, expected := range cases {
		if actual := normalizeDomain(input); actual != expected {
			t.Fatalf("normalizeDomain(%q) = %q, want %q", input, actual, expected)
		}
	}
}
