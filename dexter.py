import argparse
import json
import time
import re
import asyncio
import aiohttp
import random
from pathlib import Path
from urllib.parse import urljoin

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0"
]

def build_base_url(host: str, port: int, scheme: str | None = None) -> str:
    host = host.strip()
    if scheme:
        scheme = scheme.lower()
    else:
        scheme = "https" if port == 443 else "http"
    return f"{scheme}://{host}:{port}"

def load_rules(filepath: str) -> list:
    path = Path(filepath)
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []

async def evaluate_condition(response: aiohttp.ClientResponse, body_text: str, condition: dict) -> bool:
    c_type = condition.get("type")
    regex_pattern = condition.get("regex", "")
    
    try:
        if c_type == "header":
            key = condition.get("key")
            if not key: 
                return False
            header_val = response.headers.get(key, "")
            if regex_pattern == ".*":
                return key in response.headers
            return bool(re.search(regex_pattern, header_val))

        elif c_type == "body":
            if regex_pattern == ".*":
                return bool(body_text)
            return bool(re.search(regex_pattern, body_text))

        elif c_type == "status":
            target_status = str(condition.get("value"))
            return str(response.status) == target_status

        elif c_type == "cookie":
            for c_name, c_cookie in response.cookies.items():
                c_val = c_cookie.value
                if regex_pattern == ".*":
                    return True
                if re.search(regex_pattern, c_name) or re.search(regex_pattern, c_val):
                    return True
            return False
            
    except re.error:
        return False
    
    return False

async def check_matchers(response: aiohttp.ClientResponse, body_text: str, matchers: list) -> tuple:
    evidence = []
    detected = False

    for matcher in matchers:
        conditions = matcher.get("conditions", [])
        if not conditions: 
            continue
        
        all_conditions_met = True
        temp_evidence = []

        for cond in conditions:
            if await evaluate_condition(response, body_text, cond):
                c_type = cond.get("type")
                key = cond.get("key", "")
                val = cond.get("value", "")
                regex = cond.get("regex", "")
                
                if c_type == "header":
                    header_val = response.headers.get(key)
                    temp_evidence.append(f"Header '{key}: {header_val}' matched '{regex}'")
                elif c_type == "status":
                    temp_evidence.append(f"Status {response.status} matched {val}")
                elif c_type == "body":
                    temp_evidence.append(f"Body matched regex '{regex}'")
                elif c_type == "cookie":
                     temp_evidence.append(f"Cookie matched regex '{regex}'")
            else:
                all_conditions_met = False
                break
        
        if all_conditions_met:
            detected = True
            evidence.extend(temp_evidence)
            break

    return detected, evidence

async def collect_fingerprint(session: aiohttp.ClientSession, base_url: str, timeout_val: int) -> dict:
    fp = {}
    start = time.time()
    timeout = aiohttp.ClientTimeout(total=timeout_val)
    url = urljoin(base_url, "/")
    
    try:
        async with session.get(url, timeout=timeout) as r_get:
            content = await r_get.read()
            fp["server"] = r_get.headers.get("Server")
            fp["x_powered_by"] = r_get.headers.get("X-Powered-By")
            fp["status"] = r_get.status
            fp["content_length"] = len(content)
            fp["cl_mismatch"] = False

        async with session.head(url, timeout=timeout) as r_head:
            head_cl = r_head.headers.get("Content-Length")
            if head_cl and head_cl.isdigit():
                if int(head_cl) != fp["content_length"]:
                    fp["cl_mismatch"] = True
                    
        async with session.options(url, timeout=timeout) as r_opt:
            fp["allow_methods"] = r_opt.headers.get("Allow", "None")
            
    except Exception as ex:
        return {"error": str(ex)}

    fp["elapsed_ms"] = int((time.time() - start) * 1000)
    return fp

async def test_module(module: dict, base_url: str, timeout_val: int, insecure: bool, host_header: str) -> dict:
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

    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "*/*"
    }
    headers.update(custom_headers)
    if host_header:
        headers["Host"] = host_header

    timeout = aiohttp.ClientTimeout(total=timeout_val)
    
    try:
        connector = aiohttp.TCPConnector(ssl=not insecure)
        async with aiohttp.ClientSession(connector=connector, cookie_jar=aiohttp.DummyCookieJar()) as session:
            async with session.request(method=method, url=url, headers=headers, timeout=timeout, allow_redirects=True) as response:
                result["status"] = response.status
                body_bytes = await response.content.read(500000)
                body_text = body_bytes.decode('utf-8', errors='ignore')
                
                is_detected, evidence = await check_matchers(response, body_text, module.get("matchers", []))
                
                if is_detected:
                    result["detected"] = True
                    result["evidence"] = evidence
    except Exception as e:
        result["evidence"] = [str(e)]

    return result

async def enumerate_modules(base_url: str, modules: list, timeout_val: int, workers: int, insecure: bool, host_header: str) -> dict:
    results = {}
    sem = asyncio.Semaphore(workers)
    
    async def bounded_test(mod):
        async with sem:
            return await test_module(mod, base_url, timeout_val, insecure, host_header)
            
    tasks = [asyncio.create_task(bounded_test(mod)) for mod in modules]
    responses = await asyncio.gather(*tasks)
    
    for r in responses:
        results[r["name"]] = r
        
    return results

async def main_async(args):
    print("--- Dexter v2.1.0 (Async) ---")
    print(f"[*] Target: {args.host}:{args.port}")
    
    modules = load_rules(args.rules)
    if not modules:
        return

    base_url = build_base_url(args.host, args.port, args.scheme)
    
    host_header = args.host_header
    if not host_header and args.sni_host:
        host_header = args.sni_host

    connector = aiohttp.TCPConnector(ssl=not args.insecure)
    async with aiohttp.ClientSession(connector=connector, cookie_jar=aiohttp.DummyCookieJar()) as session:
        fp = await collect_fingerprint(session, base_url, args.timeout)
        print(f"   Server: {fp.get('server', 'Unknown')}")
        print(f"   Tech: {fp.get('x_powered_by', 'None')}")
        print(f"   Allowed Methods: {fp.get('allow_methods', 'None')}")
        if fp.get("cl_mismatch"):
            print("   [!] Content-Length mismatch detected (Possible WAF/Dynamic Content)")

    results = await enumerate_modules(base_url, modules, args.timeout, args.workers, args.insecure, host_header)

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

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--rules", default="modules.json")
    parser.add_argument("--scheme", choices=["http", "https"])
    parser.add_argument("--workers", type=int, default=100)
    parser.add_argument("--timeout", type=int, default=5)
    parser.add_argument("--sni-host")
    parser.add_argument("--host-header")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--json-output")
    
    args = parser.parse_args()
    asyncio.run(main_async(args))

if __name__ == "__main__":
    main()