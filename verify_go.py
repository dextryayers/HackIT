import sys
import os
import asyncio
import json

# Add project root to path
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from hackit.subdomain.go_bridge import get_engine

async def test():
    engine = get_engine()
    print(f"Engine available: {engine.available}")
    
    if not engine.available:
        print("Go engine not available. Please install Go.")
        return

    # Test 1: Brute Force
    print("\n[Test 1] Testing run_brute_force...")
    results = engine.run_brute_force("google.com", ["mail", "drive", "docs"], threads=10, timeout=2000)
    print(f"Results: {len(results)}")
    for res in results:
        print(f"  - {res['subdomain']}: {res['ips']}")
        
    # Test 2: Resolve List
    print("\n[Test 2] Testing resolve_list...")
    domains = ["www.google.com", "ns1.google.com", "invalid-subdomain-xyz-123.google.com"]
    results = engine.resolve_list(domains, threads=10, timeout=2000)
    print(f"Results: {len(results)}")
    for res in results:
        print(f"  - {res['subdomain']}: {res['ips']}")

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(test())