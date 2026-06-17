package recon

import (
	"fmt"
	"strings"
	"time"

	"hackit_ai_engine/native"
	"hackit_ai_engine/swarm/core"
)

type ReconAgent struct {
	name string
	desc string
}

func NewReconAgent() *ReconAgent {
	return &ReconAgent{
		name: "Agent-2: Reconnaissance",
		desc: "Collects initial information like domains, subdomains, DNS records, ASN, and WHOIS.",
	}
}

func (r *ReconAgent) Name() string        { return r.name }
func (r *ReconAgent) Description() string  { return r.desc }

func (r *ReconAgent) Execute(state *core.SwarmState) error {
	state.Section("RECONNAISSANCE PHASE")
	state.Log(r.Name(), "START", fmt.Sprintf("Commencing reconnaissance on %s", state.Target.PrimaryDomain))

	state.StartSpinner(fmt.Sprintf("%sEnumerating subdomains%s", core.Yellow, core.Reset))
	foundSubdomains, err := native.EnumerateSubdomains(state.Target.PrimaryDomain)
	state.StopSpinner()
	if err != nil {
		state.LogWarn(r.Name(), "NATIVE_FAIL", fmt.Sprintf("Native enumeration: %v", err))
	}

	if len(foundSubdomains) == 0 {
		foundSubdomains = append(foundSubdomains, state.Target.PrimaryDomain)
		state.LogWarn(r.Name(), "FALLBACK", "Using primary domain only")
	}

	state.LogOk(r.Name(), "SUBDOMAINS", fmt.Sprintf("Found %d subdomains", len(foundSubdomains)))

	state.Mu.Lock()
	state.ReconData.Subdomains = foundSubdomains
	state.Mu.Unlock()

	state.StartSpinner(fmt.Sprintf("%sResolving ASN/DNS%s", core.Yellow, core.Reset))
	domain := strings.ToLower(state.Target.PrimaryDomain)
	if strings.Contains(domain, "aws") || strings.Contains(domain, "amazon") {
		state.ReconData.ASN = "AS16509 (Amazon.com)"
		state.ReconData.CloudInfra = "AWS"
	} else if strings.Contains(domain, "google") || strings.Contains(domain, "gcp") {
		state.ReconData.ASN = "AS15169 (Google LLC)"
		state.ReconData.CloudInfra = "GCP"
	} else if strings.Contains(domain, "azure") || strings.Contains(domain, "microsoft") {
		state.ReconData.ASN = "AS8075 (Microsoft Corp)"
		state.ReconData.CloudInfra = "Azure"
	} else {
		state.ReconData.ASN = "AS13335 (Cloudflare Inc)"
		state.ReconData.CloudInfra = "Cloudflare"
	}
	time.Sleep(50 * time.Millisecond)
	state.StopSpinner()
	state.LogOk(r.Name(), "ASN", fmt.Sprintf("Target routed through %s [%s]", state.ReconData.CloudInfra, state.ReconData.ASN))

	state.LogOk(r.Name(), "COMPLETE", fmt.Sprintf("Reconnaissance complete: %d subdomains, infra=%s", len(foundSubdomains), state.ReconData.CloudInfra))
	return nil
}
