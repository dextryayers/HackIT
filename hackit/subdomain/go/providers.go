package main

import (
	"bufio"
	"encoding/base64"
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

// -----------------------------------------------------------------------------
// HELPER FUNCTIONS
// -----------------------------------------------------------------------------

// PASSIVE PROVIDERS (OSINT)
// -----------------------------------------------------------------------------

func queryCrtSh(domain string) []string {
	// wildcards for crt.sh - Use a more specific query to avoid crt.sh hanging
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	// Try a second format if the first fails
	url2 := fmt.Sprintf("https://crt.sh/?q=%s&output=json", domain)

	var resp *http.Response
	var err error

	// Attempt URL 1
	for i := 0; i < 3; i++ {
		resp, err = safeGet(url, 60*time.Second)
		if err == nil && resp.StatusCode == 200 {
			break
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(2 * time.Second)
	}

	// Fallback to URL 2
	if err != nil || resp == nil || resp.StatusCode != 200 {
		for i := 0; i < 2; i++ {
			resp, err = safeGet(url2, 60*time.Second)
			if err == nil && resp.StatusCode == 200 {
				break
			}
			if resp != nil {
				resp.Body.Close()
			}
			time.Sleep(2 * time.Second)
		}
	}

	if err != nil || resp == nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil
	}

	var found []string
	for _, e := range entries {
		lines := strings.Split(e.NameValue, "\n")
		for _, l := range lines {
			sub := cleanSubdomain(l, domain)
			if sub != "" {
				found = append(found, sub)
			}
		}
	}
	return unique(found)
}

func queryCertDB(domain string) []string {
	url := fmt.Sprintf("https://certdb.com/api-open/domain/%s", domain)
	return scrape(url, domain)
}

func queryBinaryEdge(domain string) []string {
	url := fmt.Sprintf("https://api.binaryedge.io/v2/query/domains/subdomain/%s", domain)
	return scrape(url, domain)
}

func queryDNSDB(domain string) []string {
	url := fmt.Sprintf("https://api.dnsdb.info/lookup/rrset/name/*.%s", domain)
	return scrape(url, domain)
}

func queryPassiveTotal(domain string) []string {
	url := fmt.Sprintf("https://api.passivetotal.org/v2/enrichment/subdomains?query=%s", domain)
	return scrape(url, domain)
}

func scrape(url, domain string) []string {
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	// Better regex for subdomain extraction from HTML
	re := regexp.MustCompile(`[a-zA-Z0-9.-]+\.` + regexp.QuoteMeta(domain))
	matches := re.FindAllString(string(body), -1)

	var found []string
	for _, m := range matches {
		sub := cleanSubdomain(m, domain)
		if sub != "" {
			found = append(found, sub)
		}
	}
	return unique(found)
}

func queryGoogleCT(domain string) []string {
	url := fmt.Sprintf("https://www.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?domain=%s&include_expired=true&include_subdomains=true", domain)
	return scrape(url, domain)
}

func queryFacebookCT(domain string) []string {
	// Note: Facebook CT requires an access token usually, but sometimes public scraping works for some endpoints
	// For now, let's add a placeholder or a public-ish endpoint if exists
	return nil
}

func querySSLMate(domain string) []string {
	url := fmt.Sprintf("https://sslmate.com/ctsearch_api/v2/certs?domain=%s", domain)
	return scrape(url, domain)
}

func queryHybridAnalysis(domain string) []string {
	url := fmt.Sprintf("https://www.hybrid-analysis.com/search?query=domain:%s", domain)
	return scrape(url, domain)
}

func queryAsk(domain string) []string {
	var found []string
	for i := 1; i <= 3; i++ {
		url := fmt.Sprintf("https://www.ask.com/web?q=site:%s&page=%d", domain, i)
		found = append(found, scrape(url, domain)...)
		time.Sleep(300 * time.Millisecond)
	}
	return unique(found)
}

func queryGitHub(domain string) []string {
	url := fmt.Sprintf("https://github.com/search?q=%s&type=Code", domain)
	return scrape(url, domain)
}

func queryGitLab(domain string) []string {
	url := fmt.Sprintf("https://gitlab.com/search?search=%s&group_id=&project_id=&repository_ref=&scope=blobs", domain)
	return scrape(url, domain)
}

func queryBitbucket(domain string) []string {
	url := fmt.Sprintf("https://bitbucket.org/repo/all?name=%s", domain)
	return scrape(url, domain)
}

func querySourceForge(domain string) []string {
	url := fmt.Sprintf("https://sourceforge.net/directory/?q=%s", domain)
	return scrape(url, domain)
}

func queryGitea(domain string) []string {
	// Gitea is often self-hosted, but we can check some common instances or just skip if no global search
	return nil
}

func queryChaos(domain string) []string {
	url := "https://chaos-data.projectdiscovery.io/index.json"
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	var result struct {
		Results []struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
	}
	for _, r := range result.Results {
		if strings.EqualFold(r.Name, domain) {
			resp2, err := safeGet(r.URL, 60*time.Second)
			if err != nil || resp2 == nil {
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
	return nil
}

func queryHackerTarget(domain string) []string {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	
	var found []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if parts := strings.Split(line, ","); len(parts) > 0 {
			sub := cleanSubdomain(parts[0], domain)
			if sub != "" {
				found = append(found, sub)
			}
		}
	}
	return unique(found)
}

func queryOTX(domain string) []string {
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	var result struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
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

func queryWayback(domain string) []string {
	url := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey", domain)
	resp, err := safeGet(url, 45*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()

	var result [][]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
	}

	var found []string
	for i, entry := range result {
		if i == 0 { continue } // Skip header
		if len(entry) > 0 {
			// Extract domain from URL
			rawURL := entry[0]
			cleanURL := strings.TrimPrefix(strings.TrimPrefix(rawURL, "http://"), "https://")
			parts := strings.Split(cleanURL, "/")
			sub := cleanSubdomain(parts[0], domain)
			if sub != "" {
				found = append(found, sub)
			}
		}
	}
	return unique(found)
}

func queryUrlScan(domain string) []string {
	url := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=100", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
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
		return nil
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

func queryVirusTotal(domain string) []string {
	url := fmt.Sprintf("https://www.virustotal.com/ui/domains/%s/subdomains?limit=40", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	var result struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
	}
	var found []string
	for _, d := range result.Data {
		sub := cleanSubdomain(d.ID, domain)
		if sub != "" {
			found = append(found, sub)
		}
	}
	return found
}

func queryAnubis(domain string) []string {
	url := fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	var result []string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
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

func queryRapiddns(domain string) []string {
	return scrape(fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", domain), domain)
}

func queryDNSDumpster(domain string) []string {
	url := "https://dnsdumpster.com/"
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	csrfRegex := regexp.MustCompile(`name='csrfmiddlewaretoken' value='(.*?)'`)
	csrfMatches := csrfRegex.FindStringSubmatch(string(body))
	if len(csrfMatches) < 2 {
		return nil
	}
	csrfToken := csrfMatches[1]
	data := fmt.Sprintf("csrfmiddlewaretoken=%s&targetip=%s", csrfToken, domain)
	req, _ := http.NewRequest("POST", url, strings.NewReader(data))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", url)
	req.Header.Set("Cookie", fmt.Sprintf("csrftoken=%s", csrfToken))
	resp2, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp2.Body.Close()
	body2, _ := ioutil.ReadAll(resp2.Body)
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(string(body2), -1)
	return unique(matches)
}

func querySubdomainCenter(domain string) []string {
	url := fmt.Sprintf("https://api.subdomain.center/?domain=%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	var result []string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
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

func queryYandex(domain string) []string {
	var found []string
	seen := make(map[string]struct{})
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	for page := 0; page < 3; page++ {
		url := fmt.Sprintf("https://yandex.com/search/?text=site:%s&lr=1&p=%d", domain, page)
		resp, err := safeGet(url, 30*time.Second)
		if err != nil || resp == nil {
			continue
		}
		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		matches := re.FindAllString(string(body), -1)
		for _, m := range matches {
			sub := cleanSubdomain(m, domain)
			if sub != "" {
				if _, ok := seen[sub]; !ok {
					seen[sub] = struct{}{}
					found = append(found, sub)
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return found
}

func queryColumbus(domain string) []string {
	url := fmt.Sprintf("https://columbus.elox.2host.io/%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	var result []string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
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

func queryThreatCrowd(domain string) []string {
	return scrape(fmt.Sprintf("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s", domain), domain)
}

func queryNetcraft(domain string) []string {
	return scrape(fmt.Sprintf("https://searchdns.netcraft.com/?restriction=site+ends+with&host=%s", domain), domain)
}

func queryBaidu(domain string) []string {
	var found []string
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	for _, pn := range []int{0, 10, 20} {
		url := fmt.Sprintf("https://www.baidu.com/s?wd=site:%s&rn=50&pn=%d", domain, pn)
		resp, err := safeGet(url, 30*time.Second)
		if err != nil || resp == nil {
			continue
		}
		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		matches := re.FindAllString(string(body), -1)
		for _, m := range matches {
			sub := cleanSubdomain(m, domain)
			if sub != "" {
				found = append(found, sub)
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return unique(found)
}

func queryYahoo(domain string) []string {
	var found []string
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	for _, b := range []int{1, 11, 21} {
		url := fmt.Sprintf("https://search.yahoo.com/search?p=site:%s&b=%d", domain, b)
		resp, err := safeGet(url, 30*time.Second)
		if err != nil || resp == nil {
			continue
		}
		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		matches := re.FindAllString(string(body), -1)
		for _, m := range matches {
			sub := cleanSubdomain(m, domain)
			if sub != "" {
				found = append(found, sub)
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return unique(found)
}

func queryBing(domain string) []string {
	var found []string
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	for _, first := range []int{1, 11, 21} {
		url := fmt.Sprintf("https://www.bing.com/search?q=site:%s&count=50&first=%d", domain, first)
		resp, err := safeGet(url, 30*time.Second)
		if err != nil || resp == nil {
			continue
		}
		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		matches := re.FindAllString(string(body), -1)
		for _, m := range matches {
			sub := cleanSubdomain(m, domain)
			if sub != "" {
				found = append(found, sub)
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return unique(found)
}

func queryGoogle(domain string) []string {
	var found []string
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	for _, start := range []int{0, 10, 20} {
		url := fmt.Sprintf("https://www.google.com/search?q=site:%s&num=50&start=%d", domain, start)
		resp, err := safeGet(url, 30*time.Second)
		if err != nil || resp == nil {
			continue
		}
		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		matches := re.FindAllString(string(body), -1)
		for _, m := range matches {
			sub := cleanSubdomain(m, domain)
			if sub != "" {
				found = append(found, sub)
			}
		}
		time.Sleep(400 * time.Millisecond)
	}
	return unique(found)
}

func queryDuckDuckGo(domain string) []string {
	var found []string
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	for _, s := range []int{0, 50, 100} {
		url := fmt.Sprintf("https://duckduckgo.com/html/?q=site:%s&s=%d", domain, s)
		resp, err := safeGet(url, 30*time.Second)
		if err != nil || resp == nil {
			continue
		}
		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		matches := re.FindAllString(string(body), -1)
		for _, m := range matches {
			sub := cleanSubdomain(m, domain)
			if sub != "" {
				found = append(found, sub)
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return unique(found)
}

func queryShodan(domain string) []string {
	url := fmt.Sprintf("https://www.shodan.io/domain/%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(string(body), -1)
	return unique(matches)
}

func querySecurityTrails(domain string) []string {
	url := fmt.Sprintf("https://securitytrails.com/domain/%s/subdomains", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(string(body), -1)
	return unique(matches)
}

func queryAhrefs(domain string) []string {
	url := fmt.Sprintf("https://ahrefs.com/backlink-checker?target=%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(string(body), -1)
	return unique(matches)
}

func queryFullHunt(domain string) []string {
	url := fmt.Sprintf("https://fullhunt.io/api/v1/domain/%s/subdomains", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	var result struct {
		Hosts []string `json:"hosts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
	}
	var found []string
	for _, h := range result.Hosts {
		sub := cleanSubdomain(h, domain)
		if sub != "" {
			found = append(found, sub)
		}
	}
	return found
}

func queryBuiltWith(domain string) []string {
	url := fmt.Sprintf("https://builtwith.com/%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(string(body), -1)
	return unique(matches)
}

func queryCensys(domain string) []string {
	url := fmt.Sprintf("https://search.censys.io/search?resource=hosts&q=%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(string(body), -1)
	return unique(matches)
}

func queryFofa(domain string) []string {
	query := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("domain=\"%s\"", domain)))
	url := fmt.Sprintf("https://fofa.info/result?qbase64=%s", query)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(string(body), -1)
	return unique(matches)
}

func queryZoomeye(domain string) []string {
	url := fmt.Sprintf("https://www.zoomeye.org/search?q=site:%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(string(body), -1)
	return unique(matches)
}

func queryLeakix(domain string) []string {
	url := fmt.Sprintf("https://leakix.net/search?scope=leak&q=%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(string(body), -1)
	return unique(matches)
}

func queryIntelx(domain string) []string {
	url := fmt.Sprintf("https://intelx.io/?s=%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(string(body), -1)
	return unique(matches)
}

func queryPublicWWW(domain string) []string {
	url := fmt.Sprintf("https://publicwww.com/websites/%s/", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(string(body), -1)
	return unique(matches)
}

func queryCriminalIP(domain string) []string {
	url := fmt.Sprintf("https://www.criminalip.io/en/asset/search?query=%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(string(body), -1)
	return unique(matches)
}

func queryQuake(domain string) []string {
	url := fmt.Sprintf("https://quake.360.net/quake/#/searchResult?searchVal=domain:\"%s\"", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(string(body), -1)
	return unique(matches)
}

func queryDnsHistory(domain string) []string {
	url := fmt.Sprintf("https://dnshistory.org/subdomains/1/%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(string(body), -1)
	return unique(matches)
}

func queryViewDNS(domain string) []string {
	url := fmt.Sprintf("https://viewdns.info/iphistory/?domain=%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(string(body), -1)
	return unique(matches)
}

func queryDNSRepo(domain string) []string {
	url := fmt.Sprintf("https://dnsrepo.com/subdomains/%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(string(body), -1)
	return unique(matches)
}

func queryDnsWatch(domain string) []string {
	url := fmt.Sprintf("https://dnswatch.info/dns/lookup?hostname=%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(string(body), -1)
	return unique(matches)
}

func queryReverseIP(domain string) []string {
	url := fmt.Sprintf("https://api.hackertarget.com/reverseiplookup/?q=%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(string(body), -1)
	return unique(matches)
}

func querySitedossier(domain string) []string {
	return scrape(fmt.Sprintf("http://www.sitedossier.com/parentdomain/%s", domain), domain)
}

func queryRiddler(domain string) []string {
	url := fmt.Sprintf("https://riddler.io/api/search/subdomain/%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	var result []struct {
		Subdomain string `json:"subdomain"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
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
	// Use Free API for better results than scraping
	url := fmt.Sprintf("https://freeapi.robtex.com/pdns/forward/%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		// Fallback to scrape if API fails
		return scrape(fmt.Sprintf("https://www.robtex.com/dns-lookup/%s", domain), domain)
	}
	defer resp.Body.Close()

	var results []struct {
		Data string `json:"data"`
		Type string `json:"type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return scrape(fmt.Sprintf("https://www.robtex.com/dns-lookup/%s", domain), domain)
	}

	var found []string
	for _, r := range results {
		if r.Type == "A" || r.Type == "AAAA" || r.Type == "CNAME" {
			sub := cleanSubdomain(r.Data, domain)
			if sub != "" {
				found = append(found, sub)
			}
		}
	}
	return unique(found)
}

func queryBufferOver(domain string) []string {
	url := fmt.Sprintf("https://dns.bufferover.run/dns?q=.%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	var result struct {
		FDNS_A []string `json:"FDNS_A"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
	}
	var found []string
	for _, entry := range result.FDNS_A {
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
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	var result struct {
		StatusCode string   `json:"status_code"`
		Results    []string `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
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

func querySonar(domain string) []string {
	url := fmt.Sprintf("https://sonar.omnisint.io/subdomains/%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	var result []string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
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

func queryCommonCrawl(domain string) []string {
	indexes := []string{"CC-MAIN-2024-10", "CC-MAIN-2024-18", "CC-MAIN-2024-22"}
	var found []string
	seen := make(map[string]struct{})
	for _, index := range indexes {
		url := fmt.Sprintf("http://index.commoncrawl.org/%s-index?url=*.%s&output=json", index, domain)
		resp, err := safeGet(url, 60*time.Second)
		if err != nil || resp == nil {
			continue
		}
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
		resp.Body.Close()
		time.Sleep(200 * time.Millisecond)
	}
	return found
}

func queryWhoisXMLAPI(domain string) []string {
	url := fmt.Sprintf("https://subdomains.whoisxmlapi.com/api/v1?domainName=%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(string(body), -1)
	return unique(matches)
}

func queryDomainBigData(domain string) []string {
	url := fmt.Sprintf("https://domainbigdata.com/%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(string(body), -1)
	return unique(matches)
}

func queryDnslytics(domain string) []string {
	url := fmt.Sprintf("https://dnslytics.com/domain/%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(string(body), -1)
	return unique(matches)
}

func queryC99(domain string) []string {
	url := fmt.Sprintf("https://api.c99.nl/subdomainfinder?key=FREE&domain=%s&json", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	var result struct {
		Subdomains []struct {
			Subdomain string `json:"subdomain"`
		} `json:"subdomains"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
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

func querySublist3r(domain string) []string {
	url := fmt.Sprintf("https://api.sublist3r.com/search.php?domain=%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	var result []string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
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

func queryCertSpotter(domain string) []string {
	url := fmt.Sprintf("https://api.certspotter.org/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	var result []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
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

func queryDigitorus(domain string) []string {
	url := fmt.Sprintf("https://certdb.com/api-open/domain/%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	var result struct {
		Results []struct {
			Domain string `json:"domain"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
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
	url := fmt.Sprintf("https://app.netlas.io/api/domains/?q=domain:*.%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
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
		return nil
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

func querySiteAdvisor(domain string) []string {
	url := fmt.Sprintf("https://www.siteadvisor.com/sitereport.html?url=%s", domain)
	resp, err := safeGet(url, 30*time.Second)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	re := regexp.MustCompile(`([\w\.-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(string(body), -1)
	return unique(matches)
}

func queryBeVigil(domain string) []string {
	url := fmt.Sprintf("https://bevigil.com/api/v1/all/subdomains/%s", domain)
	return scrape(url, domain)
}

func queryGrepApp(domain string) []string {
	url := fmt.Sprintf("https://grep.app/api/search?q=%s", domain)
	return scrape(url, domain)
}
