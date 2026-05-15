# HackIt AI Specialized Command Triggers

COMMAND_MODES = {
    # [ CORE ]
    "halo": "Activate full intelligence mode. Perform a comprehensive analysis of the current state and provide general assistance.",
    "summary": "Provide a concise summary of all discovered artifacts and scan results so far.",
    "explain": "Translate technical findings into clear, human-readable explanations for stakeholders.",
    "report": "Generate a structured, professional-grade pentesting report based on the collected intelligence.",

    # [ ANALYSIS ]
    "insight": "Identify the most critical insights and core vulnerabilities discovered in the infrastructure.",
    "risk": "Perform a detailed risk assessment. Calculate business impact, exploitability, and overall severity.",
    "score": "Assign a numerical security score (0-100) based on current findings and industry standards.",
    "priority": "Identify the high-value targets and assets that should be prioritized for further testing.",
    "anomaly": "Detect unusual patterns or behaviors in network traffic, headers, or system responses.",
    "pattern": "Search for recurring misconfigurations, auth weaknesses, or API design flaws across the target.",
    "logic": "Analyze the application's business logic for potential bypasses, race conditions, or state-machine flaws.",
    "behavior": "Analyze how the system behaves under specific conditions or malformed inputs.",
    "context": "Evaluate findings within the specific business and technical context of the target organization.",

    # [ CORRELATION ]
    "correlate": "Correlate multiple data points to find complex, multi-step attack chains.",
    "graph": "Map the relationships between different nodes, services, and endpoints in a visual/logical graph.",
    "flow": "Analyze the end-to-end data flow through the application and backend services.",
    "boundary": "Identify trust boundaries and evaluate how data crosses between different security zones.",
    "zone": "Classify assets into Public, DMZ, or Internal zones based on their exposure and connectivity.",
    "dependency": "Identify service dependencies and potential third-party supply chain risks.",

    # [ ATTACK INTEL ]
    "attack": "Generate detailed, step-by-step attack paths to compromise specific objectives.",
    "chain": "Build a vulnerability chain where one minor finding leads to a major compromise.",
    "vector": "Identify the primary attack vectors currently exposed on the target surface.",
    "entry": "Pinpoint the weakest entry points into the infrastructure.",
    "surface": "Define the total attack surface area and identify any shadow IT or forgotten assets.",
    "scenario": "Simulate complex attack scenarios (e.g., Ransomware, Data Exfiltration) based on real gaps.",

    # [ API & AUTH ]
    "remaining": "Check and report the remaining token/API quota if available.",
    "session": "Analyze session management mechanisms for potential hijacking, fixation, or entropy issues.",

    # [ CLOUD & INFRA ]
    "cloud": "Specialize in Cloud-native vulnerabilities (S3 buckets, IAM roles, Metadata services).",
    "origin": "Attempt to predict the real Origin IP address by bypassing CDN/WAF protections.",
    "waf": "Analyze the WAF/IPS protection mechanisms and identify potential bypass heuristics.",

    # [ OSINT ]
    "osint": "Correlate external OSINT data with internal scan results for a broader threat profile.",
    "employee": "Identify employee patterns, email structures, and potential social engineering targets.",
    "leak": "Search for potential data leaks, exposed secrets, or credential dumps related to the target.",

    # [ STRATEGY ]
    "strategy": "Recommend a comprehensive testing strategy based on the current reconnaissance data.",
    "next": "Recommend the immediate next steps the analyst should take for maximum impact.",
    "focus": "Identify the critical area where the analyst should focus all attention right now.",
    "plan": "Generate a detailed exploitation plan for the confirmed vulnerabilities.",

    # [ OUTPUT ]
    "json": "Format all intelligence output strictly as JSON for integration with other tools.",
    "clean": "Provide a clean, concise response with minimal fluff.",
    "detail": "Provide a comprehensive, high-fidelity response with all technical details included.",
    "dev": "Output technical details specifically for developers and security engineers.",
    "human": "Ensure the output is easy to read and professionally formatted.",

    # [ ADVANCED ]
    "deep": "Perform a deep-dive analysis. Spend more tokens to think harder and explore edge cases.",
    "auto": "Enter autonomous analysis mode. Correlate and report everything without further input.",
    "adaptive": "Enable adaptive learning. Adjust analysis style based on previous analyst feedback.",
    "learn": "Identify and save recurring patterns for future recognition.",
}

def get_command_prompt(command: str) -> str:
    """Return the specialized prompt extension for a slash command"""
    mode_desc = COMMAND_MODES.get(command.lower())
    if not mode_desc:
        return ""
    
    return f"\n[ MODE: {command.upper()} ]\nSpecialized Task: {mode_desc}\nFocus your intelligence strictly on this objective."
