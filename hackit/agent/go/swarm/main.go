package main

import (
	"flag"
	"fmt"
	"os"

	"hackit_ai_engine/swarm/orchestrator"
)

func main() {
	domainPtr := flag.String("domain", "", "Target primary domain (e.g., example.com)")
	scopePtr := flag.String("scope", "passive", "Scope level (passive, active_stealth, aggressive)")

	flag.Parse()

	if *domainPtr == "" {
		fmt.Println("[!] Fatal: -domain argument is required to launch the swarm.")
		fmt.Println("Usage: ./swarm_engine -domain <target.com> [-scope <passive|aggressive>]")
		os.Exit(1)
	}

	// Initialize the absolute master Agent-20
	masterNode := orchestrator.NewOrchestratorAgent()

	// Ignite the DAG
	err := masterNode.Execute(*domainPtr, *scopePtr)
	if err != nil {
		fmt.Printf("\n[!] Swarm Critical Failure: %v\n", err)
		os.Exit(1)
	}
}
