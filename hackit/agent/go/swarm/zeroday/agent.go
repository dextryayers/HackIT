package zeroday

import (
	"fmt"
	"strings"
	"time"

	"hackit_ai_engine/swarm/core"
)

type ZeroDayAgent struct {
	name string
	desc string
}

func NewZeroDayAgent() *ZeroDayAgent {
	return &ZeroDayAgent{
		name: "Agent-23: Zero-Day Heuristic Analyzer",
		desc: "Flags banner tokens worth manual source review. Produces leads, never findings.",
	}
}

func (a *ZeroDayAgent) Name() string        { return a.name }
func (a *ZeroDayAgent) Description() string { return a.desc }

// Execute records banner observations as leads only.  A substring in a banner
// is not a vulnerability: the previous version matched the first three
// characters of each pattern against svc.Tech and emitted Critical 9.5
// "Potential 0-Day" findings for essentially any web service.
func (a *ZeroDayAgent) Execute(state *core.SwarmState) error {
	state.Section("ZERO-DAY ANALYSIS PHASE")
	state.Log(a.Name(), "START", "Collecting banner observations for manual code review...")

	state.Mu.RLock()
	services := state.Discovered
	state.Mu.RUnlock()

	start := time.Now()
	state.StartSpinner(fmt.Sprintf("%sReviewing %d service banners%s", core.Yellow, len(services), core.Reset))

	// Tokens that indicate a component worth a source-code review when they
	// appear verbatim in a banner.  They never constitute proof on their own.
	reviewTokens := []string{
		"eval(", "exec(", "system(", "popen(", "shell_exec(", "passthru(",
		"dangerouslySetInnerHTML", "new Function(",
		"child_process", "process.binding",
	}

	analyzedCount := 0
	seen := map[string]bool{}
	var leads []string
	for _, svc := range services {
		if svc.Port != 80 && svc.Port != 443 && svc.Port != 8080 && svc.Port != 8443 && svc.Port != 3000 && svc.Port != 5000 {
			continue
		}
		analyzedCount++
		banner := svc.Banner
		if banner == "" {
			continue
		}
		lower := strings.ToLower(banner)
		for _, tok := range reviewTokens {
			if !strings.Contains(lower, tok) {
				continue
			}
			lead := fmt.Sprintf("banner token %q on %s:%d — review the component source", tok, svc.IP, svc.Port)
			if seen[lead] {
				continue
			}
			seen[lead] = true
			leads = append(leads, lead)
		}
	}

	state.StopSpinner()

	state.Mu.Lock()
	if len(leads) > 0 {
		state.ContextData["zeroday_leads"] = leads
	}
	state.Mu.Unlock()

	for i, lead := range leads {
		if i >= 5 {
			break
		}
		state.Log(a.Name(), "LEAD", lead)
	}

	elapsed := time.Since(start).Round(time.Millisecond)
	state.LogOk(a.Name(), "RESULT", fmt.Sprintf("Reviewed %d web banners, %d review leads in %s (no findings emitted)",
		analyzedCount, len(leads), elapsed))
	return nil
}
