package main

import (
	"fmt"
	"strings"
)

// AttackVector represents a single path from discovery to exploitation.
type AttackVector struct {
	Port        int
	Service     string
	Vulnerability string
	Impact      string
}

// GenerateVulnFlowchart creates a Mermaid TD (Top-Down) flowchart string from attack vectors.
func GenerateVulnFlowchart(target string, vectors []AttackVector) string {
	if len(vectors) == 0 {
		return "No vulnerabilities found to chart."
	}

	var sb strings.Builder
	
	sb.WriteString(fmt.Sprintf("### Vulnerability Flowchart: %s\n\n", target))
	sb.WriteString("```mermaid\n")
	sb.WriteString("flowchart TD\n")
	
	// Root Node
	sb.WriteString(fmt.Sprintf("    Target[\"🎯 %s\"]\n\n", target))
	
	for i, vec := range vectors {
		// Create unique node IDs
		portNode := fmt.Sprintf("Port%d_%d", vec.Port, i)
		vulnNode := fmt.Sprintf("Vuln%d_%d", vec.Port, i)
		impactNode := fmt.Sprintf("Impact%d_%d", vec.Port, i)
		
		// Define Nodes
		sb.WriteString(fmt.Sprintf("    %s(\"🔌 Port %d (%s)\")\n", portNode, vec.Port, vec.Service))
		sb.WriteString(fmt.Sprintf("    %s{\"🧨 %s\"}\n", vulnNode, vec.Vulnerability))
		sb.WriteString(fmt.Sprintf("    %s[\"🔥 %s\"]\n", impactNode, vec.Impact))
		
		// Define Relationships
		sb.WriteString(fmt.Sprintf("    Target --> %s\n", portNode))
		sb.WriteString(fmt.Sprintf("    %s -- \"Analyzed\" --> %s\n", portNode, vulnNode))
		sb.WriteString(fmt.Sprintf("    %s -. \"Exploited\" .-> %s\n\n", vulnNode, impactNode))
		
		// Styling Impact Nodes
		if strings.Contains(strings.ToLower(vec.Impact), "rce") || strings.Contains(strings.ToLower(vec.Impact), "root") || strings.Contains(strings.ToLower(vec.Impact), "critical") {
			sb.WriteString(fmt.Sprintf("    style %s fill:#f00,stroke:#333,stroke-width:4px,color:#fff\n", impactNode))
		} else {
			sb.WriteString(fmt.Sprintf("    style %s fill:#f90,stroke:#333,stroke-width:2px,color:#fff\n", impactNode))
		}
	}
	
	sb.WriteString("```\n")
	return sb.String()
}
