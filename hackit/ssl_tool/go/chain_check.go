package main

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type ChainReport struct {
	ChainDepth      int      `json:"chain_depth"`
	RootCA          string   `json:"root_ca"`
	RootOrg         string   `json:"root_org"`
	IntermediateCNs []string `json:"intermediate_cns"`
	RootExpired     bool     `json:"root_expired"`
	RootExpiryDays  int      `json:"root_expiry_days"`
	OCSPResponders  []string `json:"ocsp_responders"`
	CRLURLs         []string `json:"crl_urls"`
	OCSPResponded   bool     `json:"ocsp_responded"`
	Issues          []string `json:"issues"`
	Score           int      `json:"score"`
}

func scanChain(cert *x509.Certificate, chain []*x509.Certificate) ChainReport {
	r := ChainReport{
		IntermediateCNs: make([]string, 0),
		Issues:          make([]string, 0),
	}
	r.ChainDepth = len(chain)

	if len(chain) > 0 {
		root := chain[len(chain)-1]
		r.RootCA = root.Subject.CommonName
		r.RootOrg = strings.Join(root.Subject.Organization, ", ")
		r.RootExpired = time.Now().After(root.NotAfter)
		r.RootExpiryDays = int(time.Until(root.NotAfter).Hours() / 24)
	}

	for i := 1; i < len(chain)-1; i++ {
		r.IntermediateCNs = append(r.IntermediateCNs, chain[i].Subject.CommonName)
	}

	if cert.OCSPServer != nil {
		r.OCSPResponders = cert.OCSPServer
	} else {
		r.OCSPResponders = make([]string, 0)
	}
	if cert.CRLDistributionPoints != nil {
		r.CRLURLs = cert.CRLDistributionPoints
	} else {
		r.CRLURLs = make([]string, 0)
	}

	for _, ocspURL := range cert.OCSPServer {
		resp, err := http.Get(ocspURL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				r.OCSPResponded = true
				break
			}
		}
	}

	r.Issues = buildChainIssues(&r)
	r.Score = calcChainScore(&r)
	return r
}

func buildChainIssues(r *ChainReport) []string {
	issues := make([]string, 0)
	if r.RootExpired {
		issues = append(issues, fmt.Sprintf("Root CA certificate expired %d days ago", -r.RootExpiryDays))
	}
	if r.RootExpiryDays < 30 && !r.RootExpired {
		issues = append(issues, fmt.Sprintf("Root CA expires in %d days", r.RootExpiryDays))
	}
	if len(r.IntermediateCNs) == 0 && r.ChainDepth < 2 {
		issues = append(issues, "No intermediate certificates in chain")
	}
	if len(r.OCSPResponders) == 0 {
		issues = append(issues, "No OCSP responders configured")
	}
	if len(r.CRLURLs) == 0 {
		issues = append(issues, "No CRL distribution points configured")
	}
	if !r.OCSPResponded && len(r.OCSPResponders) > 0 {
		issues = append(issues, "OCSP responder did not respond (may be blocked or unavailable)")
	}
	return issues
}

func calcChainScore(r *ChainReport) int {
	s := 100
	if r.RootExpired {
		s = 0
		return s
	}
	if r.RootExpiryDays < 30 {
		s -= 20
	}
	if len(r.IntermediateCNs) == 0 && r.ChainDepth < 2 {
		s -= 15
	}
	if len(r.OCSPResponders) == 0 {
		s -= 10
	}
	if len(r.CRLURLs) == 0 {
		s -= 5
	}
	if !r.OCSPResponded && len(r.OCSPResponders) > 0 {
		s -= 10
	}
	if s < 0 {
		s = 0
	}
	return s
}

func printChainReport(r ChainReport) {
	fmt.Printf("\n  [+] Certificate Chain Analysis:")
	fmt.Printf("\n    %-24s : %d", "Chain Depth", r.ChainDepth)
	if r.RootCA != "" {
		fmt.Printf("\n    %-24s : %s", "Root CA", r.RootCA)
		fmt.Printf("\n    %-24s : %s", "Root Org", r.RootOrg)
		expCol := "\033[32m"
		if r.RootExpired {
			expCol = "\033[31m"
		} else if r.RootExpiryDays < 30 {
			expCol = "\033[33m"
		}
		fmt.Printf("\n    %-24s : %s%d days\033[0m", "Root Expiry", expCol, r.RootExpiryDays)
	}
	if len(r.IntermediateCNs) > 0 {
		fmt.Printf("\n    %-24s : %s", "Intermediates", strings.Join(r.IntermediateCNs, ", "))
	}
	fmt.Printf("\n    %-24s : %d URLs", "OCSP Responders", len(r.OCSPResponders))
	fmt.Printf("\n    %-24s : %d URLs", "CRL Endpoints", len(r.CRLURLs))
	fmt.Printf("\n    %-24s : %v", "OCSP Reachable", r.OCSPResponded)
	fmt.Printf("\n    %-24s : %d/100", "Chain Score", r.Score)
	if len(r.Issues) > 0 {
		fmt.Printf("\n\n    [!] Chain Issues (%d):", len(r.Issues))
		for _, iss := range r.Issues {
			fmt.Printf("\n      - %s", iss)
		}
	}
	fmt.Println()
}
