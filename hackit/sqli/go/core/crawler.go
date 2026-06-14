package core

import (
	"fmt"
	"net/url"
	"strings"
)

type CrawledParam struct {
	URL     string
	Method  string
	Params  map[string]string
	Depth   int
	Forms   []FormInfo
}

type FormInfo struct {
	Action string
	Method string
	Fields []string
}

func (e *Engine) CrawlParameters(startURL string, maxDepth int) []CrawledParam {
	e.logInfo(fmt.Sprintf("Crawling %s for injection points (depth: %d)...", startURL, maxDepth))

	discovered := []CrawledParam{}
	visited := map[string]bool{}
	toVisit := []string{startURL}
	depth := 0

	for len(toVisit) > 0 && depth < maxDepth {
		current := toVisit[0]
		toVisit = toVisit[1:]

		if visited[current] {
			continue
		}
		visited[current] = true

		body, _, _, err := e.Request("", "")
		if err != nil {
			continue
		}

		cp := CrawledParam{
			URL:    current,
			Method: "GET",
			Params: extractURLParams(current),
			Depth:  depth,
			Forms:  extractForms(body),
		}
		if len(cp.Params) > 0 || len(cp.Forms) > 0 {
			discovered = append(discovered, cp)
		}

		newLinks := extractLinks(body, current)
		for _, link := range newLinks {
			if !visited[link] && len(discovered) < 20 {
				toVisit = append(toVisit, link)
			}
		}
		depth++
	}

	e.logInfo(fmt.Sprintf("Discovered %d injection points (depth: %d)", len(discovered), maxDepth))
	return discovered
}

func extractURLParams(rawURL string) map[string]string {
	result := map[string]string{}
	u, err := url.Parse(rawURL)
	if err != nil {
		return result
	}
	for k, v := range u.Query() {
		if len(v) > 0 {
			result[k] = v[0]
		}
	}
	return result
}

func extractForms(body string) []FormInfo {
	forms := []FormInfo{}
	bodyLower := strings.ToLower(body)

	for {
		formStart := strings.Index(bodyLower, "<form")
		if formStart < 0 {
			break
		}
		formEnd := strings.Index(bodyLower[formStart:], "</form>")
		if formEnd < 0 {
			break
		}
		formBlock := body[formStart : formStart+formEnd+7]

		f := FormInfo{
			Method: "GET",
			Fields: []string{},
		}

		if strings.Contains(strings.ToLower(formBlock), "method=\"post\"") {
			f.Method = "POST"
		}

		actionIdx := strings.Index(strings.ToLower(formBlock), "action=\"")
		if actionIdx >= 0 {
			actionEnd := strings.Index(formBlock[actionIdx+8:], "\"")
			if actionEnd >= 0 {
				f.Action = formBlock[actionIdx+8 : actionIdx+8+actionEnd]
			}
		}

		for {
			inputStart := strings.Index(strings.ToLower(formBlock), "name=\"")
			if inputStart < 0 {
				break
			}
			nameEnd := strings.Index(formBlock[inputStart+6:], "\"")
			if nameEnd < 0 {
				break
			}
			fname := formBlock[inputStart+6 : inputStart+6+nameEnd]
			if fname != "" {
				f.Fields = append(f.Fields, fname)
			}
			formBlock = formBlock[inputStart+6+nameEnd:]
		}

		forms = append(forms, f)
		bodyLower = bodyLower[formStart+formEnd+7:]
	}

	return forms
}

func extractLinks(body string, baseURL string) []string {
	links := []string{}
	bodyLower := strings.ToLower(body)

	for {
		hrefStart := strings.Index(bodyLower, "href=\"")
		if hrefStart < 0 {
			hrefStart = strings.Index(bodyLower, "href='")
			if hrefStart < 0 {
				break
			}
			quote := "'"
			linkStart := hrefStart + 6
			linkEnd := strings.Index(body[linkStart:], quote)
			if linkEnd < 0 {
				break
			}
			link := body[linkStart : linkStart+linkEnd]
			if strings.HasPrefix(link, "/") || strings.HasPrefix(link, "http") || strings.HasPrefix(link, "?") {
				if strings.Contains(link, "=") || strings.Contains(link, "?") {
					links = append(links, link)
				}
			}
			bodyLower = bodyLower[linkStart+linkEnd+1:]
		} else {
			linkStart := hrefStart + 6
			linkEnd := strings.Index(body[linkStart:], "\"")
			if linkEnd < 0 {
				break
			}
			link := body[linkStart : linkStart+linkEnd]
			if strings.HasPrefix(link, "/") || strings.HasPrefix(link, "http") || strings.HasPrefix(link, "?") {
				if strings.Contains(link, "=") || strings.Contains(link, "?") {
					links = append(links, link)
				}
			}
			bodyLower = bodyLower[linkStart+linkEnd+1:]
		}
	}

	return links
}
