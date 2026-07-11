"""
Module Template for HackIT OSINT modules.
Copy this file to modules/ and rename to implement a new scanner.
All 250+ modules should follow this pattern for consistency.
"""
from module_base import BaseScanner
from typing import List
from models import IntelligenceFinding

class CustomScanner(BaseScanner):
    name = "custom_scanner"
    timeout = 15
    SUPPORTED_TYPES = ["Domain", "URL"]  # or ["IP"], ["Email"], etc.

    async def crawl(self, client, target: str) -> List[IntelligenceFinding]:
        findings = []

        # 1. Fetch data
        resp = await self.safe_request(f"https://api.example.com/v1/{target}")
        if not resp:
            return findings

        # 2. Parse response
        try:
            data = await resp.json()
        except Exception:
            return findings

        # 3. Create findings using self.finding()
        for item in data.get("results", []):
            finding = self.finding(
                entity=item.get("name", "unknown"),
                ftype="Custom Type",
                source=f"Python:{self.name}",
                confidence="Medium",
                color="slate",
                raw_data=str(item),
            )
            if finding:
                findings.append(finding)

        return findings


# Backward compatibility: allow direct `crawl(target, client)` calls from orchestrator
async def crawl(target: str, client) -> List[IntelligenceFinding]:
    scanner = CustomScanner(target, client)
    return await scanner.crawl(client, target)
