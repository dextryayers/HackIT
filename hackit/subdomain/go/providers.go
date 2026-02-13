package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// ProviderFunc is the signature for all passive source functions
type ProviderFunc func(string) []string

func queryCrtSh(domain string) []string {
	// wildcards for crt.sh
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	var resp *http.Response
	var err error

	// Retry logic
	for i := 0; i < 5; i++ {
		resp, err = safeGet(url, 90*time.Second)
		if err == nil && resp.StatusCode == 200 {
			break
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(3 * time.Second)
	}

	if err != nil || resp == nil || resp.StatusCode != 200 {
		return []string{}
	}
	defer resp.Body.Close()

	// Use JSON decoder for efficiency instead of reading whole body
	var entries []struct {
		NameValue string `json:"name_value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return []string{}
	}

	var found []string
	seen := make(map[string]struct{})
	for _, e := range entries {
		lines := strings.Split(e.NameValue, "\n")
		for _, l := range lines {
			l = strings.TrimSpace(l)
			l = strings.TrimPrefix(l, "*.")
			if l != "" && !strings.Contains(l, "*") {
				if _, ok := seen[l]; !ok {
					seen[l] = struct{}{}
					found = append(found, l)
				}
			}
		}
	}
	return found
}

func queryChaos(domain string) []string {
	url := fmt.Sprintf("https://chaos-data.projectdiscovery.io/index.json")
	resp, err := safeGet(url, 30*time.Second)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()

	var result struct {
		Results []struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return []string{}
	}

	for _, r := range result.Results {
		if strings.EqualFold(r.Name, domain) {
			resp2, err := safeGet(r.URL, 60*time.Second)
			if err != nil {
				continue
			}
			defer resp2.Body.Close()

			var found []string
			scanner := bufio.NewScanner(resp2.Body)
			for scanner.Scan() {
				sub := cleanSubdomain(scanner.Text(), domain)
				if sub != "" {
					found = append(found, sub)
				}
			}
			return found
		}
	}
	return []string{}
}

func queryC99(domain string) []string {
	url := fmt.Sprintf("https://api.c99.nl/subdomainfinder?key=FREE&domain=%s&json", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()

	var result struct {
		Subdomains []struct {
			Subdomain string `json:"subdomain"`
		} `json:"subdomains"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		// Fallback to plain text if JSON fails
		body, _ := ioutil.ReadAll(resp.Body)
		re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
		matches := re.FindAllString(string(body), -1)
		return matches
	}

	var found []string
	for _, s := range result.Subdomains {
		sub := cleanSubdomain(s.Subdomain, domain)
		if sub != "" {
			found = append(found, sub)
		}
	}
	return found
}

func queryRiddler(domain string) []string {
	url := fmt.Sprintf("https://riddler.io/api/search/subdomain/%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()

	var result []struct {
		Subdomain string `json:"subdomain"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return []string{}
	}

	var found []string
	for _, r := range result {
		sub := cleanSubdomain(r.Subdomain, domain)
		if sub != "" {
			found = append(found, sub)
		}
	}
	return found
}

func queryRobtex(domain string) []string {
	url := fmt.Sprintf("https://www.robtex.com/dns-lookup/%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	content := string(body)

	// Improved regex for Robtex
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(content, -1)

	var found []string
	for _, m := range matches {
		sub := cleanSubdomain(m, domain)
		if sub != "" {
			found = append(found, sub)
		}
	}
	return found
}

func getCommonCrawlIndexes() []string {
	// Dynamically fetch CommonCrawl index list, fallback to static if fetch fails
	fallback := []string{"CC-MAIN-2024-10", "CC-MAIN-2024-18", "CC-MAIN-2024-22"}
	resp, err := safeGet("http://index.commoncrawl.org/collinfo.json", 30*time.Second)
	if err != nil || resp == nil {
		if resp != nil {
			resp.Body.Close()
		}
		return fallback
	}
	defer resp.Body.Close()
	var infos []struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&infos); err != nil || len(infos) == 0 {
		return fallback
	}
	// Take up to first 5 indexes to avoid excessive queries
	var out []string
	for i := 0; i < len(infos) && i < 5; i++ {
		id := strings.TrimSpace(infos[i].ID)
		if id != "" {
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		return fallback
	}
	return out
}

func queryCommonCrawl(domain string) []string {
	indexes := getCommonCrawlIndexes()
	var found []string
	seen := make(map[string]struct{})

	for _, index := range indexes {
		url := fmt.Sprintf("http://index.commoncrawl.org/%s-index?url=*.%s&output=json", index, domain)
		resp, err := safeGet(url, 60*time.Second)
		if err != nil || resp == nil {
			continue
		}
		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			var entry struct {
				URL string `json:"url"`
			}
			if err := json.Unmarshal(scanner.Bytes(), &entry); err == nil {
				sub := cleanSubdomain(entry.URL, domain)
				if sub != "" {
					if _, ok := seen[sub]; !ok {
						seen[sub] = struct{}{}
						found = append(found, sub)
					}
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return found
}

func querySonar(domain string) []string {
	url := fmt.Sprintf("https://sonar.omnisint.io/subdomains/%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()

	var result []string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return []string{}
	}

	var found []string
	for _, s := range result {
		sub := cleanSubdomain(s, domain)
		if sub != "" {
			found = append(found, sub)
		}
	}
	return found
}

func queryAnubis(domain string) []string {
	url := fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()

	var result []string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return []string{}
	}

	var found []string
	for _, s := range result {
		sub := cleanSubdomain(s, domain)
		if sub != "" {
			found = append(found, sub)
		}
	}
	return found
}

func queryDigitorus(domain string) []string {
	url := fmt.Sprintf("https://certdb.com/api-open/domain/%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()

	var result struct {
		Results []struct {
			Domain string `json:"domain"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return []string{}
	}

	var found []string
	for _, r := range result.Results {
		sub := cleanSubdomain(r.Domain, domain)
		if sub != "" {
			found = append(found, sub)
		}
	}
	return found
}

func queryNetlas(domain string) []string {
	// Passive DNS via Netlas (no API key for public data if available, but let's use common pattern)
	url := fmt.Sprintf("https://app.netlas.io/api/domains/?q=domain:*.%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()

	var result struct {
		Items []struct {
			Data struct {
				Domain string `json:"domain"`
			} `json:"data"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return []string{}
	}

	var found []string
	for _, item := range result.Items {
		sub := cleanSubdomain(item.Data.Domain, domain)
		if sub != "" {
			found = append(found, sub)
		}
	}
	return found
}

func querySubdomainCenter(domain string) []string {
	url := fmt.Sprintf("https://api.subdomain.center/?domain=%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()

	var result []string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return []string{}
	}

	var found []string
	for _, s := range result {
		sub := cleanSubdomain(s, domain)
		if sub != "" {
			found = append(found, sub)
		}
	}
	return found
}

func querySitedossier(domain string) []string {
	url := fmt.Sprintf("http://www.sitedossier.com/parentdomain/%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	content := string(body)

	// Regex for links like /site/sub.domain.com
	re := regexp.MustCompile(`/site/([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllStringSubmatch(content, -1)

	var found []string
	for _, m := range matches {
		if len(m) > 1 {
			found = append(found, m[1])
		}
	}
	return found
}

func queryHackerTarget(domain string) []string {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	lines := strings.Split(string(body), "\n")

	var found []string
	for _, l := range lines {
		parts := strings.Split(l, ",")
		if len(parts) >= 1 {
			sub := cleanSubdomain(parts[0], domain)
			if sub != "" {
				found = append(found, sub)
			}
		}
	}
	return found
}

func queryAlienVault(domain string) []string {
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()

	var result struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return []string{}
	}

	var found []string
	for _, entry := range result.PassiveDNS {
		sub := cleanSubdomain(entry.Hostname, domain)
		if sub != "" {
			found = append(found, sub)
		}
	}
	return found
}

func queryThreatCrowd(domain string) []string {
	url := fmt.Sprintf("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()

	var result struct {
		Subdomains []string `json:"subdomains"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return []string{}
	}

	var found []string
	for _, s := range result.Subdomains {
		sub := cleanSubdomain(s, domain)
		if sub != "" {
			found = append(found, sub)
		}
	}
	return found
}

func queryRapiddns(domain string) []string {
	url := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	content := string(body)

	// Simple regex extract since it's HTML table
	re := regexp.MustCompile(`<td>([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)</td>`)
	matches := re.FindAllStringSubmatch(content, -1)

	var found []string
	for _, m := range matches {
		if len(m) > 1 {
			found = append(found, m[1])
		}
	}
	return found
}

func querySublist3r(domain string) []string {
	url := fmt.Sprintf("https://api.sublist3r.com/search.php?domain=%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()

	var result []string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return []string{}
	}

	var found []string
	for _, s := range result {
		sub := cleanSubdomain(s, domain)
		if sub != "" {
			found = append(found, sub)
		}
	}
	return found
}

func queryWayback(domain string) []string {
	url := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey", domain)
	resp, err := safeGet(url, 60*time.Second)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()

	var result [][]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return []string{}
	}

	var found []string
	for i, row := range result {
		if i == 0 {
			continue
		} // Skip header
		if len(row) > 0 {
			sub := cleanSubdomain(row[0], domain)
			if sub != "" {
				found = append(found, sub)
			}
		}
	}
	return found
}

func queryUrlScan(domain string) []string {
	url := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=100", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()

	var result struct {
		Results []struct {
			Page struct {
				Domain string `json:"domain"`
			} `json:"page"`
		} `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return []string{}
	}

	var found []string
	for _, r := range result.Results {
		sub := cleanSubdomain(r.Page.Domain, domain)
		if sub != "" {
			found = append(found, sub)
		}
	}
	return found
}

func queryBufferOver(domain string) []string {
	url := fmt.Sprintf("https://dns.bufferover.run/dns?q=.%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()

	var result struct {
		FDNS_A []string `json:"FDNS_A"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return []string{}
	}

	var found []string
	for _, entry := range result.FDNS_A {
		// Format: "1.2.3.4,sub.domain.com"
		parts := strings.Split(entry, ",")
		if len(parts) >= 2 {
			sub := cleanSubdomain(parts[1], domain)
			if sub != "" {
				found = append(found, sub)
			}
		}
	}
	return found
}

func queryThreatMiner(domain string) []string {
	url := fmt.Sprintf("https://api.threatminer.org/v2/domain.php?q=%s&rt=5", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()

	var result struct {
		StatusCode string   `json:"status_code"`
		Results    []string `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return []string{}
	}

	var found []string
	if result.StatusCode == "200" {
		for _, s := range result.Results {
			sub := cleanSubdomain(s, domain)
			if sub != "" {
				found = append(found, sub)
			}
		}
	}
	return found
}

func queryCertSpotter(domain string) []string {
	url := fmt.Sprintf("https://api.certspotter.org/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()

	var result []struct {
		DNSNames []string `json:"dns_names"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return []string{}
	}

	var found []string
	for _, entry := range result {
		for _, name := range entry.DNSNames {
			sub := cleanSubdomain(name, domain)
			if sub != "" {
				found = append(found, sub)
			}
		}
	}
	return found
}

func queryDNSDumpster(domain string) []string {
	// url := "https://dnsdumpster.com/"
	// DNSDumpster requires CSRF token, but sometimes a simple scrape of common locations works
	// For now, let's use a known public API if available or just a placeholder for future implementation
	// Actually, let's try to scrape it properly or use another source
	return []string{}
}

func queryBaidu(domain string) []string {
	pages := []int{0, 10, 20}
	var found []string
	seen := make(map[string]struct{})
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)

	for _, pn := range pages {
		url := fmt.Sprintf("https://www.baidu.com/s?wd=site:%s&rn=50&pn=%d", domain, pn)
		resp, err := safeGet(url, 30*time.Second)
		if err != nil || resp == nil {
			continue
		}
		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		content := string(body)

		matches := re.FindAllString(content, -1)
		for _, m := range matches {
			sub := cleanSubdomain(m, domain)
			if sub != "" {
				if _, ok := seen[sub]; !ok {
					seen[sub] = struct{}{}
					found = append(found, sub)
				}
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return found
}

func queryYahoo(domain string) []string {
	offsets := []int{1, 11, 21}
	var found []string
	seen := make(map[string]struct{})
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)

	for _, b := range offsets {
		url := fmt.Sprintf("https://search.yahoo.com/search?p=site:%s&b=%d", domain, b)
		resp, err := safeGet(url, 30*time.Second)
		if err != nil || resp == nil {
			continue
		}
		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		content := string(body)

		matches := re.FindAllString(content, -1)
		for _, m := range matches {
			sub := cleanSubdomain(m, domain)
			if sub != "" {
				if _, ok := seen[sub]; !ok {
					seen[sub] = struct{}{}
					found = append(found, sub)
				}
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return found
}

func queryBing(domain string) []string {
	offsets := []int{1, 11, 21}
	var found []string
	seen := make(map[string]struct{})
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)

	for _, first := range offsets {
		url := fmt.Sprintf("https://www.bing.com/search?q=site:%s&count=50&first=%d", domain, first)
		resp, err := safeGet(url, 30*time.Second)
		if err != nil || resp == nil {
			continue
		}
		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		content := string(body)

		matches := re.FindAllString(content, -1)
		for _, m := range matches {
			sub := cleanSubdomain(m, domain)
			if sub != "" {
				if _, ok := seen[sub]; !ok {
					seen[sub] = struct{}{}
					found = append(found, sub)
				}
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return found
}

func queryGoogle(domain string) []string {
	starts := []int{0, 10, 20}
	var found []string
	seen := make(map[string]struct{})
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)

	for _, start := range starts {
		url := fmt.Sprintf("https://www.google.com/search?q=site:%s&num=50&start=%d", domain, start)
		resp, err := safeGet(url, 30*time.Second)
		if err != nil || resp == nil {
			continue
		}
		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		content := string(body)

		matches := re.FindAllString(content, -1)
		for _, m := range matches {
			sub := cleanSubdomain(m, domain)
			if sub != "" {
				if _, ok := seen[sub]; !ok {
					seen[sub] = struct{}{}
					found = append(found, sub)
				}
			}
		}
		time.Sleep(400 * time.Millisecond)
	}
	return found
}

func queryDuckDuckGo(domain string) []string {
	starts := []int{0, 50, 100}
	var found []string
	seen := make(map[string]struct{})
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)

	for _, s := range starts {
		url := fmt.Sprintf("https://duckduckgo.com/html/?q=site:%s&s=%d", domain, s)
		resp, err := safeGet(url, 30*time.Second)
		if err != nil || resp == nil {
			continue
		}
		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		content := string(body)

		matches := re.FindAllString(content, -1)
		for _, m := range matches {
			sub := cleanSubdomain(m, domain)
			if sub != "" {
				if _, ok := seen[sub]; !ok {
					seen[sub] = struct{}{}
					found = append(found, sub)
				}
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return found
}

func queryShodan(domain string) []string {
	url := fmt.Sprintf("https://www.shodan.io/domain/%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return []string{}
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	content := string(body)

	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(content, -1)

	var found []string
	seen := make(map[string]struct{})
	for _, m := range matches {
		sub := cleanSubdomain(m, domain)
		if sub != "" {
			if _, ok := seen[sub]; !ok {
				seen[sub] = struct{}{}
				found = append(found, sub)
			}
		}
	}
	return found
}

func querySecurityTrails(domain string) []string {
	// SecurityTrails often requires API key but they have a public page
	url := fmt.Sprintf("https://securitytrails.com/domain/%s/subdomains", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return []string{}
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	content := string(body)

	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(content, -1)

	var found []string
	seen := make(map[string]struct{})
	for _, m := range matches {
		sub := cleanSubdomain(m, domain)
		if sub != "" {
			if _, ok := seen[sub]; !ok {
				seen[sub] = struct{}{}
				found = append(found, sub)
			}
		}
	}
	return found
}

func queryAhrefs(domain string) []string {
	url := fmt.Sprintf("https://ahrefs.com/backlink-checker?target=%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return []string{}
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	content := string(body)

	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(content, -1)

	var found []string
	seen := make(map[string]struct{})
	for _, m := range matches {
		sub := cleanSubdomain(m, domain)
		if sub != "" {
			if _, ok := seen[sub]; !ok {
				seen[sub] = struct{}{}
				found = append(found, sub)
			}
		}
	}
	return found
}
