#!/usr/bin/env python3
import argparse
import logging
import json
import time
import hashlib
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any
from pathlib import Path
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- CONFIGURATION ---
TOOL_NAME = "Dexter"
VERSION = "2.0.0"
DEVELOPER = "Stallion77"
DEFAULT_RULES_FILE = "modules.json"

logger = logging.getLogger(__name__)

# --- UTILS & CORE LOGIC ---

def build_base_url(host: str, port: int, scheme: str | None = None) -> str:
    host = host.strip()
    if scheme:
        scheme = scheme.lower()
    else:
        scheme = "https" if port == 443 else "http"
    return f"{scheme}://{host}:{port}"

def create_session(retries: int = 3, backoff: float = 0.5) -> requests.Session:
    """Creates a requests Session with Retry strategy."""
    session = requests.Session()
    retry_strategy = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    # Default Headers
    session.headers.update({
        "User-Agent": f"{TOOL_NAME}/{VERSION} (Security Scan)",
        "Accept": "*/*"
    })
    return session

def load_rules(filepath: str) -> List[Dict]:
    """Loads detection rules from a JSON file."""
    path = Path(filepath)
    if not path.exists():
        logger.error("Rules file not found: %s", filepath)
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            rules = json.load(f)
        logger.info("Loaded %d detection modules from %s", len(rules), filepath)
        return rules
    except json.JSONDecodeError as e:
        logger.error("Invalid JSON format in %s: %s", filepath, e)
        return []

# --- ENGINE: DYNAMIC RULE EVALUATION ---

def evaluate_condition(response: requests.Response, condition: Dict) -> bool:
    """Evaluates a single condition (header regex, body regex, status code)."""
    c_type = condition.get("type")
    regex_pattern = condition.get("regex", "")
    
    try:
        if c_type == "header":
            key = condition.get("key")
            if not key: return False
            header_val = response.headers.get(key, "")
            if regex_pattern == ".*": # Just check existence
                return key in response.headers
            return bool(re.search(regex_pattern, header_val))

        elif c_type == "body":
            body = response.text or ""
            return bool(re.search(regex_pattern, body))

        elif c_type == "status":
            target_status = str(condition.get("value"))
            return str(response.status_code) == target_status

        elif c_type == "cookie":
            # Check if any cookie name or value matches the regex
            for c_name, c_val in response.cookies.items():
                if re.search(regex_pattern, c_name) or re.search(regex_pattern, c_val):
                    return True
            return False
            
    except re.error as e:
        logger.error("Invalid regex in rule: %s", e)
        return False
    
    return False

def check_matchers(response: requests.Response, matchers: List[Dict]) -> (bool, List[str]):
    """
    Evaluates matchers. 
    Logic: Matchers are OR'ed. Inside a matcher, conditions are AND'ed.
    Returns: (Detected_Bool, Evidence_List)
    """
    evidence = []
    detected = False

    for matcher in matchers:
        conditions = matcher.get("conditions", [])
        if not conditions: 
            continue
        
        all_conditions_met = True
        temp_evidence = []

        for cond in conditions:
            if evaluate_condition(response, cond):
                c_type = cond.get("type")
                key = cond.get("key", "")
                val = cond.get("value", "")
                regex = cond.get("regex", "")
                
                if c_type == "header":
                    header_val = response.headers.get(key)
                    temp_evidence.append(f"Header '{key}: {header_val}' matched '{regex}'")
                elif c_type == "status":
                    temp_evidence.append(f"Status {response.status_code} matched {val}")
                elif c_type == "body":
                    temp_evidence.append(f"Body matched regex '{regex}'")
                elif c_type == "cookie":
                     temp_evidence.append(f"Cookie matched regex '{regex}'")
            else:
                all_conditions_met = False
                break # One condition failed in this matcher
        
        if all_conditions_met:
            detected = True
            evidence.extend(temp_evidence)
            break # We found a matching rule set, no need to check others for this module

    return detected, evidence

# --- WORKER FUNCTIONS ---

def collect_fingerprint(session: requests.Session, base_url: str, timeout: int = 5) -> Dict:
    fp = {}
    start = time.time()
    try:
        url = urljoin(base_url, "/")
        r_get = session.get(url, timeout=timeout)
        r_head = session.head(url, timeout=timeout)
        r_opt = session.options(url, timeout=timeout) # Might fail often
    except requests.RequestException as ex:
        logger.debug("Fingerprint requests partial fail: %s", ex)
        return {"error": str(ex)}

    fp["server"] = r_get.headers.get("Server")
    fp["x_powered_by"] = r_get.headers.get("X-Powered-By")
    fp["status"] = r_get.status_code
    fp["content_length"] = len(r_get.content)
    fp["cl_mismatch"] = False
    
    # Advanced Logic: Check if HEAD Content-Length differs from GET body length
    head_cl = r_head.headers.get("Content-Length")
    if head_cl and head_cl.isdigit():
        if int(head_cl) != len(r_get.content):
            fp["cl_mismatch"] = True # Often indicates WAF or dynamic injection
            
    fp["elapsed_ms"] = int((time.time() - start) * 1000)
    return fp

def test_module(module: Dict, session: requests.Session, base_url: str, timeout: int) -> Dict:
    name = module.get("name", "unknown")
    endpoint = module.get("endpoint", "/")
    method = module.get("method", "GET")
    custom_headers = module.get("headers", {})
    
    url = urljoin(base_url, endpoint)
    
    result = {
        "name": name,
        "detected": False,
        "evidence": [],
        "status": None
    }

    try:
        response = session.request(
            method=method,
            url=url,
            headers=custom_headers,
            timeout=timeout,
            allow_redirects=True,
            verify=session.verify
        )
        result["status"] = response.status_code
        
        is_detected, evidence = check_matchers(response, module.get("matchers", []))
        
        if is_detected:
            logger.info("[+] DETECTED: %s (%s)", name, url)
            result["detected"] = True
            result["evidence"] = evidence
        else:
            logger.debug("[-] %s not detected", name)

    except requests.RequestException as e:
        logger.debug("[!] Error testing %s: %s", name, e)
        result["evidence"] = [str(e)]

    return result

def enumerate_modules(session: requests.Session, base_url: str, modules: List[Dict], timeout: int, workers: int) -> Dict:
    results = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {
            ex.submit(test_module, mod, session, base_url, timeout): mod["name"] 
            for mod in modules
        }
        
        for fut in as_completed(futures):
            r = fut.result()
            results[r["name"]] = r
            
    return results

# --- MAIN ENTRY ---

def main():
    parser = argparse.ArgumentParser(description="Apache Module Detection Engine (JSON Rules)")
    parser.add_argument("--host", required=True, help="Target host (e.g., 192.168.1.1 or example.com)")
    parser.add_argument("--port", type=int, default=80, help="Target port")
    parser.add_argument("--rules", default=DEFAULT_RULES_FILE, help=f"Path to JSON rules file (default: {DEFAULT_RULES_FILE})")
    parser.add_argument("--scheme", choices=["http", "https"], help="Force scheme")
    parser.add_argument("--workers", type=int, default=10, help="Concurrency")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout")
    parser.add_argument("--sni-host", help="Custom SNI hostname for IP scanning")
    parser.add_argument("--host-header", help="Custom Host header")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL verification")
    parser.add_argument("--json-output", help="Save output to JSON file")
    parser.add_argument("--verbose", action="store_true", help="Debug logs")
    
    args = parser.parse_args()

    # Logging Setup
    log_fmt = "%(asctime)s - %(levelname)s - %(message)s"
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format=log_fmt)
    
    # Header & Info
    print(f"--- {TOOL_NAME} v{VERSION} ---")
    print(f"[*] Target: {args.host}:{args.port}")
    
    # Load Rules
    modules = load_rules(args.rules)
    if not modules:
        logger.critical("No rules loaded. Exiting.")
        return

    # Session Setup
    base_url = build_base_url(args.host, args.port, args.scheme)
    session = create_session()
    session.verify = not args.insecure
    
    if args.insecure:
        requests.packages.urllib3.disable_warnings()
        
    if args.host_header:
        session.headers["Host"] = args.host_header
    elif args.sni_host:
        # If scanning IP but need SNI, Host header usually needs to match SNI
        session.headers["Host"] = args.sni_host

    # 1. Fingerprinting
    logger.info("Phase 1: Fingerprinting...")
    try:
        fp = collect_fingerprint(session, base_url, args.timeout)
        print(f"   Server: {fp.get('server', 'Unknown')}")
        print(f"   Tech: {fp.get('x_powered_by', 'None')}")
        if fp.get("cl_mismatch"):
             logger.warning("   [!] Content-Length mismatch detected (Possible WAF/Dynamic Content)")
    except Exception as e:
        logger.error("Fingerprint failed: %s", e)
        fp = {"error": str(e)}

    # 2. Enumeration
    logger.info("Phase 2: Module Enumeration (%d modules)...", len(modules))
    results = enumerate_modules(session, base_url, modules, args.timeout, args.workers)

    # 3. Reporting
    detected = [r for r in results.values() if r["detected"]]
    print("\n" + "="*30)
    print(f"SCAN COMPLETE. DETECTED MODULES: {len(detected)}")
    print("="*30)
    
    for d in detected:
        print(f"[+] {d['name'].upper()}")
        for ev in d['evidence']:
            print(f"    └── {ev}")
            
    if args.json_output:
        final_data = {"target": base_url, "fingerprint": fp, "results": results}
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump(final_data, f, indent=2)
        logger.info("Results saved to %s", args.json_output)

if __name__ == "__main__":
    main()