#!/usr/bin/env python3
"""
Python Plugin/Probe Validator for HackIt Port Scanner
Validates probe definitions against the JSON schema and provides sample plugins.
"""

import json
import os
import sys
from typing import Dict, List, Any, Optional
from pathlib import Path

PROBE_SCHEMA = {
    "type": "object",
    "required": ["id", "protocol", "ports"],
    "properties": {
        "id": {"type": "string"},
        "protocol": {"type": "string", "enum": ["tcp", "udp"]},
        "ports": {"type": "array", "items": {"type": "integer"}, "minItems": 1},
        "payload_text": {"type": "string"},
        "payload_b64": {"type": "string"},
        "read_limit": {"type": "integer", "minimum": 1},
        "timeout_ms": {"type": "integer", "minimum": 100},
        "matchers": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["kind", "pattern", "weight"],
                "properties": {
                    "kind": {"type": "string", "enum": ["contains", "regex", "prefix"]},
                    "pattern": {"type": "string"},
                    "weight": {"type": "number", "minimum": 0},
                    "metadata": {"type": "object"}
                }
            }
        }
    }
}

def validate_probe(probe: Dict) -> List[str]:
    """Validate a single probe definition."""
    errors = []
    
    if "id" not in probe:
        errors.append("Missing required field: id")
    if "protocol" not in probe:
        errors.append("Missing required field: protocol")
    elif probe["protocol"] not in ["tcp", "udp"]:
        errors.append(f"Invalid protocol: {probe['protocol']}")
    if "ports" not in probe:
        errors.append("Missing required field: ports")
    elif not isinstance(probe["ports"], list) or len(probe["ports"]) == 0:
        errors.append("ports must be a non-empty array")
    
    if "matchers" in probe:
        for i, m in enumerate(probe["matchers"]):
            if "kind" not in m:
                errors.append(f"Matcher {i}: missing kind")
            elif m["kind"] not in ["contains", "regex", "prefix"]:
                errors.append(f"Matcher {i}: invalid kind: {m['kind']}")
            if "weight" in m and m["weight"] < 0:
                errors.append(f"Matcher {i}: weight must be non-negative")
    
    return errors

def validate_probes_file(filepath: Path) -> Dict[str, Any]:
    """Validate a probes JSON/YAML file."""
    result = {"file": str(filepath), "valid": True, "errors": [], "probes": 0}
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            if filepath.suffix in [".yaml", ".yml"]:
                import yaml
                data = yaml.safe_load(content)
            else:
                data = json.loads(content)
        
        if not isinstance(data, list):
            data = [data]
        
        result["probes"] = len(data)
        
        for i, probe in enumerate(data):
            errors = validate_probe(probe)
            if errors:
                result["valid"] = False
                result["errors"].append(f"Probe {i} ({probe.get('id', 'unknown')}): {errors}")
    
    except json.JSONDecodeError as e:
        result["valid"] = False
        result["errors"].append(f"JSON parse error: {e}")
    except Exception as e:
        result["valid"] = False
        result["errors"].append(f"Error: {e}")
    
    return result

def scan_directory(probes_dir: str) -> List[Dict[str, Any]]:
    """Scan a directory for probe files and validate them."""
    results = []
    path = Path(probes_dir)
    
    if not path.exists():
        print(f"Directory not found: {probes_dir}")
        return results
    
    for filepath in path.glob("*.json"):
        result = validate_probes_file(filepath)
        results.append(result)
    
    for filepath in path.glob("*.yaml"):
        result = validate_probes_file(filepath)
        results.append(result)
    
    for filepath in path.glob("*.yml"):
        result = validate_probes_file(filepath)
        results.append(result)
    
    return results

def print_results(results: List[Dict[str, Any]]):
    """Print validation results."""
    total = len(results)
    valid = sum(1 for r in results if r["valid"])
    
    print(f"\n{'='*60}")
    print(f"Probe Validation Results")
    print(f"{'='*60}")
    print(f"Total files: {total}")
    print(f"Valid: {valid}")
    print(f"Invalid: {total - valid}")
    print(f"{'='*60}\n")
    
    for r in results:
        status = "✓ VALID" if r["valid"] else "✗ INVALID"
        print(f"[{status}] {r['file']}")
        print(f"  Probes: {r['probes']}")
        if r["errors"]:
            for err in r["errors"]:
                print(f"  ERROR: {err}")
        print()

def create_sample_plugin(name: str, output_dir: str = "."):
    """Create a sample Python plugin."""
    template = f'''#!/usr/bin/env python3
"""
Sample HackIt Plugin: {name}
Place in hackit/port_scanner/scripts/ or use with --plugin flag
"""

import sys
import json
import socket
from typing import Dict, Any, List

class {name.replace("-", "_").title().replace("_", "")}Plugin:
    """Plugin for {name} enumeration."""
    
    name = "{name}"
    description = "Sample {name} plugin"
    categories = ["discovery", "safe"]
    
    def __init__(self):
        self.results = []
    
    def run(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run the plugin against a target."""
        options = options or {{}}
        port = options.get("port", 80)
        timeout = options.get("timeout", 5)
        
        result = {{
            "target": target,
            "plugin": self.name,
            "findings": []
        }}
        
        # Add your enumeration logic here
        # Example: connect and grab banner
        
        return result
    
    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse plugin output."""
        findings = []
        # Parse output and extract findings
        return findings

def main():
    """CLI entry point."""
    if len(sys.argv) < 2:
        print(f"Usage: {{sys.argv[0]}} <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    plugin = {name.replace("-", "_").title().replace("_", "")}Plugin()
    result = plugin.run(target)
    
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
'''
    
    output_path = Path(output_dir) / f"{name}.py"
    with open(output_path, 'w') as f:
        f.write(template)
    print(f"Created sample plugin: {output_path}")

def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python python_probes.py validate <probes_dir>")
        print("  python python_probes.py create <plugin_name>")
        print("  python python_probes.py create <plugin_name> <output_dir>")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "validate":
        if len(sys.argv) < 3:
            probes_dir = "probes"
        else:
            probes_dir = sys.argv[2]
        
        results = scan_directory(probes_dir)
        print_results(results)
    
    elif command == "create":
        if len(sys.argv) < 3:
            print("Error: plugin name required")
            sys.exit(1)
        
        name = sys.argv[2]
        output_dir = sys.argv[3] if len(sys.argv) > 3 else "."
        create_sample_plugin(name, output_dir)
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)

if __name__ == "__main__":
    main()
