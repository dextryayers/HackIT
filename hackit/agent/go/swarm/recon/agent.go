package recon

import (
	"fmt"
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
	parsed := state.Target.Parsed
	host := state.Target.PrimaryDomain
	state.Log(r.Name(), "START", fmt.Sprintf("Commencing reconnaissance on %s [%s]", host, parsed.Kind))

	// IP / CIDR / local targets have no public subdomains: skip OSINT noise
	// and scan the concrete seeds directly.
	if parsed.Kind != core.TargetDomain {
		seeds := parsed.ScanSeeds
		if len(seeds) == 0 {
			seeds = []string{host}
		}
		if parsed.Kind == core.TargetCIDR {
			state.Log(r.Name(), "CIDR", fmt.Sprintf("Range %s expands to %d seed hosts", host, len(seeds)))
		} else {
			state.Log(r.Name(), "DIRECT", fmt.Sprintf("%s target: probing host directly, no subdomain OSINT", parsed.Kind))
		}
		state.Mu.Lock()
		state.ReconData.Subdomains = seeds
		if state.Target.LocalTarget {
			state.ReconData.ASN = "RFC1918/LOCAL (intranet)"
			state.ReconData.CloudInfra = "Local network"
		} else {
			asn, infra := native.InferASN(host)
			state.ReconData.ASN = asn
			state.ReconData.CloudInfra = infra
		}
		state.Mu.Unlock()
		state.LogOk(r.Name(), "COMPLETE", fmt.Sprintf("Reconnaissance complete: %d direct seeds, infra=%s", len(seeds), state.ReconData.CloudInfra))
		return nil
	}

	state.StartSpinner(fmt.Sprintf("%sEnumerating subdomains%s", core.Yellow, core.Reset))
	foundSubdomains, err := native.EnumerateSubdomains(host)
	state.StopSpinner()
	if err != nil {
		state.LogWarn(r.Name(), "NATIVE_FAIL", fmt.Sprintf("Native enumeration: %v", err))
	}

	if len(foundSubdomains) == 0 {
		foundSubdomains = append(foundSubdomains, host)
		state.LogWarn(r.Name(), "FALLBACK", "Using primary domain only")
	}

	state.LogOk(r.Name(), "SUBDOMAINS", fmt.Sprintf("Found %d subdomains", len(foundSubdomains)))

	state.Mu.Lock()
	state.ReconData.Subdomains = foundSubdomains
	state.Mu.Unlock()

	state.StartSpinner(fmt.Sprintf("%sResolving ASN/DNS%s", core.Yellow, core.Reset))
	// ASN/infra from real DNS answers, never from domain-name substrings
	// (tesla.com is not Cloudflare).
	asn, infra := native.InferASN(host)
	state.ReconData.ASN = asn
	state.ReconData.CloudInfra = infra
	time.Sleep(50 * time.Millisecond)
	state.StopSpinner()
	state.LogOk(r.Name(), "ASN", fmt.Sprintf("Target routed through %s [%s]", state.ReconData.CloudInfra, state.ReconData.ASN))

	state.LogOk(r.Name(), "COMPLETE", fmt.Sprintf("Reconnaissance complete: %d subdomains, infra=%s", len(foundSubdomains), state.ReconData.CloudInfra))
	return nil
}
