package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

type TechSignature struct {
	Name     string   `json:"name"`
	Regex    []string `json:"regex"`
	Headers  []string `json:"headers"`
	Cookies  []string `json:"cookies"`
	URL      []string `json:"url"`
	Category string   `json:"category"`
}

type TechDetection struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Version  string `json:"version,omitempty"`
	Certainty string `json:"certainty"`
}

var DefaultTechDB = []TechSignature{
	{Name: "PHP", Category: "language", Headers: []string{"X-Powered-By: PHP"}, URL: []string{".php"}},
	{Name: "Nginx", Category: "server", Headers: []string{"Server: nginx"}},
	{Name: "Apache", Category: "server", Headers: []string{"Server: Apache"}},
	{Name: "Node.js", Category: "language", Headers: []string{"X-Powered-By: Express"}},
	{Name: "Python", Category: "language", Headers: []string{"Server: Python", "Server: Werkzeug"}},
	{Name: "Java", Category: "language", Headers: []string{"Server: Apache-Coyote", "Server: Jetty"}},
	{Name: "WordPress", Category: "cms", Cookies: []string{"wordpress_"}, URL: []string{"/wp-content/", "/wp-admin/"}},
	{Name: "Drupal", Category: "cms", Cookies: []string{"Drupal"}, URL: []string{"/sites/default/"}},
	{Name: "Joomla", Category: "cms", URL: []string{"/media/jui/", "/components/com_"}},
	{Name: "Laravel", Category: "framework", Cookies: []string{"laravel_session"}},
	{Name: "Django", Category: "framework", Cookies: []string{"csrftoken", "django.session"}},
	{Name: "Flask", Category: "framework", Headers: []string{"Server: Werkzeug"}},
	{Name: "Ruby on Rails", Category: "framework", Cookies: []string{"_session_id"}},
	{Name: "ASP.NET", Category: "framework", Headers: []string{"X-AspNet-Version"}, Cookies: []string{"ASP.NET_SessionId"}},
	{Name: "Cloudflare", Category: "cdn", Headers: []string{"cf-ray", "Server: cloudflare"}},
	{Name: "Akamai", Category: "cdn", Headers: []string{"AkamaiGHost"}},
	{Name: "jQuery", Category: "library", URL: []string{"/jquery.js", "/jquery.min.js"}},
	{Name: "Bootstrap", Category: "library", URL: []string{"/bootstrap.css", "/bootstrap.min.css"}},
	{Name: "Vue.js", Category: "library", URL: []string{"/vue.js", "/vue.min.js"}},
	{Name: "React", Category: "library", URL: []string{"/react.js", "/react-dom.js"}},
	{Name: "Angular", Category: "library", Regex: []string{"ng-app", "angular.js"}},
}

func DetectTechnologies(target string, client *http.Client, dbPath string) []TechDetection {
	db := DefaultTechDB
	if dbPath != "" {
		if loaded, err := LoadTechDB(dbPath); err == nil {
			db = loaded
		}
	}

	resp, err := SendRequest(client, target, "GET", "", nil)
	if err != nil { return nil }

	var detections []TechDetection
	for _, sig := range db {
		matched := false
		certainty := "low"
		for _, h := range sig.Headers {
			if strings.Contains(resp.Headers, h) {
				matched = true
				certainty = "high"
				break
			}
		}
		for _, c := range sig.Cookies {
			if strings.Contains(resp.Headers, "Set-Cookie:") && strings.Contains(resp.Headers, c) {
				matched = true
				certainty = "high"
				break
			}
		}
		for _, u := range sig.URL {
			if strings.Contains(target, u) {
				matched = true
				if certainty != "high" { certainty = "medium" }
				break
			}
		}
		if matched {
			detections = append(detections, TechDetection{
				Name: sig.Name, Category: sig.Category, Certainty: certainty,
			})
		}
	}
	return detections
}

func LoadTechDB(path string) ([]TechSignature, error) {
	data, err := os.ReadFile(path)
	if err != nil { return nil, err }
	var db []TechSignature
	err = json.Unmarshal(data, &db)
	return db, err
}

func PrintTechDetections(detections []TechDetection) {
	if noColor {
		fmt.Printf("[TECH] %d technologies detected:\n", len(detections))
		for _, d := range detections {
			fmt.Printf("  %s (%s) - %s\n", d.Name, d.Category, d.Certainty)
		}
		return
	}
	fmt.Printf("\n%s %s\n", SColor(ColorBCyan, "═══"), SColor(ColorBWhite, fmt.Sprintf("TECHNOLOGY DETECTION (%d found)", len(detections))))
	for _, d := range detections {
		fmt.Printf("  %s %s %s %s\n",
			SColor(ColorGreen, "✔"),
			SColor(ColorBWhite, d.Name),
			SColor(ColorDim, fmt.Sprintf("[%s]", d.Category)),
			SColor(ColorBlue, d.Certainty),
		)
	}
}
