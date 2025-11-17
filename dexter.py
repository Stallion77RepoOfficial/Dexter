#!/usr/bin/env python3
import argparse
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional
import json

import requests
import re
from pathlib import Path
from urllib.parse import urljoin
import hashlib
import time

logger = logging.getLogger(__name__)

TOOL_NAME = "Dexter"
VERSION = "1.0.1"
DEVELOPER = "Stallion77"


def build_base_url(host: str, port: int, scheme: str | None = None) -> str:
    host = host.strip()
    if scheme:
        scheme = scheme.lower()
    else:
        scheme = "https" if port == 443 else "http"
    return f"{scheme}://{host}:{port}"

def _has_header(r, name: str) -> bool:
    return name in r.headers


def _contains_text(r, text: str) -> bool:
    return text in (r.text or "")


def _status_is(r, status: int) -> bool:
    return r.status_code == status


def _header_contains(r, header: str, snippet: str) -> bool:
    return snippet in r.headers.get(header, "")


def _method_options(session: requests.Session, url: str, **kwargs):
    try:
        return session.options(url, timeout=kwargs.get("timeout", 5), verify=kwargs.get("verify", True))
    except requests.RequestException:
        return None


def collect_fingerprint(session: requests.Session, base_url: str, timeout: int = 5, verify: bool = True, allow_redirects: bool = True) -> Dict:
    fp: Dict[str, Optional[str]] = {}
    start = time.time()
    try:
        url = urljoin(base_url, "/")
        r_get = session.get(url, timeout=timeout, verify=verify, allow_redirects=allow_redirects)
        r_head = session.head(url, timeout=timeout, verify=verify, allow_redirects=allow_redirects)
        r_options = session.options(url, timeout=timeout, verify=verify, allow_redirects=allow_redirects)
    except requests.RequestException as ex:
        logger.debug("Fingerprint requests failed: %s", ex)
        return {"error": str(ex)}

    body = r_get.content or b""
    fp["server_header"] = r_get.headers.get("Server")
    fp["x_powered_by"] = r_get.headers.get("X-Powered-By")
    fp["content_type"] = r_get.headers.get("Content-Type")
    fp["content_encoding"] = r_get.headers.get("Content-Encoding")
    fp["allow_header"] = r_options.headers.get("Allow") if r_options is not None else None
    fp["status_get"] = r_get.status_code
    fp["status_head"] = r_head.status_code
    fp["status_options"] = r_options.status_code if r_options is not None else None
    fp["content_length_get"] = len(body)
    fp["content_hash"] = hashlib.sha256(body).hexdigest() if body else None
    fp["cookies"] = list(r_get.cookies.keys())
    fp["elapsed_ms"] = int((time.time() - start) * 1000)

    
    cl_header = r_head.headers.get("Content-Length")
    fp["head_content_length_header"] = int(cl_header) if cl_header and cl_header.isdigit() else None
    fp["content_mismatch"] = False
    if fp["content_length_get"] and fp["head_content_length_header"] and fp["content_length_get"] != fp["head_content_length_header"]:
        fp["content_mismatch"] = True

    
    fp["cors"] = r_options.headers.get("Access-Control-Allow-Origin") if r_options is not None else None

    return fp


modules_to_test = [
    {
        "name": "mod_php",
        "method": "GET",
        "endpoint": "/",
        "headers": {},
        "behavior": lambda r: (
            "php" in (r.headers.get("X-Powered-By") or "").lower()
            or "phpsessid" in str(r.cookies).lower()
            or any(marker in (r.text or "").lower() for marker in ("fatal error", "warning:"))
        )
    },
    {
        "name": "mod_wsgi",
        "method": "GET",
        "endpoint": "/",
        "headers": {},
        "behavior": lambda r: (
            "wsgi" in (r.headers.get("Server") or "").lower()
            or "mod_wsgi" in (r.text or "").lower()
        )
    },
    {
        "name": "mod_python",
        "method": "GET",
        "endpoint": "/",
        "headers": {},
        "behavior": lambda r: (
            "mod_python" in (r.text or "").lower()
            or "wsgi" in (r.text or "").lower()
        )
    },
    {
        "name": "mod_fastcgi",
        "method": "GET",
        "endpoint": "/",
        "headers": {},
        "behavior": lambda r: (
            "fcgi" in (r.headers.get("Server") or "").lower()
            or any(k.lower().startswith("x-fastcgi") for k in r.headers.keys())
        )
    },
    {
        "name": "mod_proxy_fcgi",
        "method": "GET",
        "endpoint": "/",
        "headers": {},
        "behavior": lambda r: (
            "fcgi" in (r.headers.get("Server") or "").lower()
            or "x-fastcgi-backend" in "\n".join([f"{k}:{v}" for k, v in r.headers.items()]).lower()
        )
    },
    {
        "name": "mod_deflate",
        "method": "GET",
        "endpoint": "/",
        "headers": {"Accept-Encoding": "gzip, deflate"},
        "behavior": lambda r: "gzip" in (r.headers.get("Content-Encoding") or "").lower() or "deflate" in (r.headers.get("Content-Encoding") or "").lower()
    },
    {
        "name": "mod_brotli",
        "method": "GET",
        "endpoint": "/",
        "headers": {"Accept-Encoding": "br"},
        "behavior": lambda r: "br" in (r.headers.get("Content-Encoding") or "").lower()
    },
    {
        "name": "mod_security",
        "method": "GET",
        "endpoint": "/",
        "headers": {"User-Agent": "ModSecurity-Test-Agent"},
        "behavior": lambda r: (r.status_code == 403 and "modsecurity" in (r.text or "").lower())
    },
    {
        "name": "mod_autoindex",
        "method": "GET",
        "endpoint": "/",
        "headers": {},
        "behavior": lambda r: ("Index of /" in (r.text or "") or "directory listing" in (r.text or "").lower())
    },
    {
        "name": "mod_dir",
        "method": "GET",
        "endpoint": "/",
        "headers": {},
        "behavior": lambda r: ("Index of /" in (r.text or "") or "directory listing" in (r.text or "").lower())
    },
    {
        "name": "mod_ssl",
        "method": "GET",
        "endpoint": "/",
        "headers": {},
        "behavior": lambda r: (_header_contains(r, "Strict-Transport-Security", "max-age") or "ssl" in (r.headers.get("Server") or "").lower() or "openssl" in (r.headers.get("Server") or "").lower())
    },
    {
        "name": "mod_headers",
        "method": "GET",
        "endpoint": "/",
        "headers": {},
        "behavior": lambda r: (True, [h for h in ("X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "X-XSS-Protection") if h in r.headers]) if any(h in r.headers for h in ("X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "X-XSS-Protection")) else False
    },
    {
        "name": "mod_cors",
        "method": "GET",
        "endpoint": "/",
        "headers": {},
        "behavior": lambda r: bool(r.headers.get("Access-Control-Allow-Origin"))
    },
    {
        "name": "mod_auth_basic",
        "method": "GET",
        "endpoint": "/",
        "headers": {},
        "behavior": lambda r: "basic" in (r.headers.get("WWW-Authenticate") or "").lower()
    },
    {
        "name": "mod_auth_digest",
        "method": "GET",
        "endpoint": "/",
        "headers": {},
        "behavior": lambda r: "digest" in (r.headers.get("WWW-Authenticate") or "").lower()
    },
    {
        "name": "mod_unique_id",
        "method": "GET",
        "endpoint": "/",
        "headers": {},
        "behavior": lambda r: (True, [h for h in ("Unique-Id", "X-Unique-ID", "X-Request-ID", "X-Request-Id") if h in r.headers]) if any(h in r.headers for h in ("Unique-Id", "X-Unique-ID", "X-Request-ID", "X-Request-Id")) else False
    },
    {
        "name": "mod_reqtimeout",
        "method": "GET",
        "endpoint": "/",
        "headers": {},
        "behavior": lambda r: r.status_code == 408 or ("request timeout" in (r.text or "").lower())
    },
    {
        "name": "mod_ratelimit",
        "method": "GET",
        "endpoint": "/",
        "headers": {},
        "behavior": lambda r: (True, [h for h in r.headers.keys() if h.lower().startswith("x-ratelimit") or "ratelimit" in h.lower() or "rate-limit" in h.lower()]) if any(h.lower().startswith("x-ratelimit") or "ratelimit" in h.lower() or "rate-limit" in h.lower() for h in r.headers.keys()) else False
    },
    {
        "name": "mod_remoteip",
        "method": "GET",
        "endpoint": "/",
        "headers": {"X-Forwarded-For": "10.10.10.10"},
        "behavior": lambda r: (True, [h for h in ("X-Forwarded-For", "X-Real-IP", "True-Client-IP") if h in r.headers]) if any(h in r.headers for h in ("X-Forwarded-For", "X-Real-IP", "True-Client-IP")) or ("remote ip" in (r.text or "").lower() or "client ip" in (r.text or "").lower()) else False
    },
    {
        "name": "mod_xsendfile",
        "method": "GET",
        "endpoint": "/",
        "headers": {},
        "behavior": lambda r: any(h in r.headers for h in ("X-Sendfile", "X-Accel-Redirect", "X-Accel-Buffering"))
    },
    {
        "name": "mod_cache",
        "method": "GET",
        "endpoint": "/",
        "headers": {},
        "behavior": lambda r: any(h in (h.lower() for h in r.headers.keys()) for h in ("x-cache", "x-cache-lookup", "x-cache-status")) or any(kw in (str(v) or "").upper() for kw in ("HIT", "MISS") for v in r.headers.values())
    }
    ,
    {
        "name": "mod_info",
        "method": "GET",
        "endpoint": "/server-info",
        "headers": {},
        "behavior": lambda r: ("Apache Server Information" in (r.text or "") or "Server Built" in (r.text or ""))
    },
    {
        "name": "mod_pagespeed",
        "method": "GET",
        "endpoint": "/",
        "headers": {},
        "behavior": lambda r: bool(r.headers.get("X-Mod-Pagespeed") or r.headers.get("X-Page-Speed") or "pagespeed" in (r.text or "").lower())
    },
    {
        "name": "mod_perl",
        "method": "GET",
        "endpoint": "/",
        "headers": {},
        "behavior": lambda r: ("mod_perl" in (r.headers.get("Server") or "").lower() or "mod_perl" in (r.text or "").lower() or "perl" in (r.headers.get("Server") or "").lower())
    },
    {
        "name": "mod_proxy_http",
        "method": "GET",
        "endpoint": "/",
        "headers": {},
        "behavior": lambda r: bool(r.headers.get("Via") or any("x-forwarded-" in k.lower() for k in r.headers.keys()) or "proxy" in (r.headers.get("Server") or "").lower())
    },
    {
        "name": "mod_evasive",
        "method": "GET",
        "endpoint": "/",
        "headers": {},
        "behavior": lambda r: (r.status_code in (403, 429) and any(m in (r.text or "").lower() for m in ("mod_evasive", "denied", "blacklist", "evasive", "blocked"))) or any("evasive" in h.lower() or "x-evasive" in h.lower() for h in r.headers.keys())
    },
    {
        "name": "mod_http2",
        "method": "GET",
        "endpoint": "/",
        "headers": {},
        "behavior": lambda r: bool(r.headers.get("Alt-Svc") and ("h2" in (r.headers.get("Alt-Svc") or "").lower() or "http2" in (r.headers.get("Alt-Svc") or "").lower())) or ("http2" in (r.headers.get("Server") or "").lower())
    },
    {
        "name": "mod_expires",
        "method": "GET",
        "endpoint": "/",
        "headers": {},
        "behavior": lambda r: bool(r.headers.get("Expires") or "max-age" in (r.headers.get("Cache-Control") or "").lower() or "s-maxage" in (r.headers.get("Cache-Control") or "").lower())
    }
]
    

def test_module(module: Dict, session: requests.Session, base_url: str, timeout: int = 5, verify: bool = True, allow_redirects: bool = True) -> Dict:
    url = urljoin(base_url, module["endpoint"])
    try:
        req_args = {
            "method": module["method"],
            "url": url,
            "headers": module.get("headers", {}),
            "timeout": timeout,
            "allow_redirects": allow_redirects,
            "verify": verify,
        }
        if module.get("data"):
            req_args["data"] = module["data"]
        response = session.request(**req_args)
        evidence: List[str] = []
        ok = False
        try:
            behavior_result = module["behavior"](response)
            if isinstance(behavior_result, dict):
                ok = bool(behavior_result.get("detected"))
                evidence = list(behavior_result.get("evidence", []))
            elif isinstance(behavior_result, (tuple, list)):
                ok = bool(behavior_result[0])
                if len(behavior_result) > 1:
                    evidence = behavior_result[1] if isinstance(behavior_result[1], list) else [str(behavior_result[1])]
            else:
                ok = bool(behavior_result)
        except Exception:
            ok = False
        if ok:
            if not evidence:
                evidence.append(f"pattern match in headers/body; status={response.status_code}")
            logger.info("[+] %s detected (%s)", module["name"], url)
        else:
            logger.debug("[-] %s not detected (%s)", module["name"], url)
        return {"name": module["name"], "detected": ok, "evidence": evidence, "status": getattr(response, "status_code", None), "headers": dict(response.headers), "timestamp": int(time.time())}
    except requests.RequestException as ex:
        logger.warning("[!] Error testing %s: %s", module["name"], ex)
        return {"name": module["name"], "detected": False, "evidence": [str(ex)], "status": None, "headers": {}}

def enumerate_modules(session: requests.Session, base_url: str, timeout: int = 5, verify: bool = True, allow_redirects: bool = True, workers: int = 8) -> Dict[str, Dict]:
    results: Dict[str, Dict] = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        unique_modules = []
        seen = set()
        for module in modules_to_test:
            
            name = module.get("name")
            normalized = str(name).split("/")[-1].split("\\")[-1]
            if "." in normalized:
                normalized = normalized.split(".")[0]
            normalized = normalized.lower()
            if normalized in seen:
                logger.debug("Skipping duplicate module name after normalization: %s", normalized)
                continue
            seen.add(normalized)
            mcopy = module.copy()
            mcopy["name"] = normalized
            unique_modules.append(mcopy)

        futures = {ex.submit(test_module, module, session, base_url, timeout, verify, allow_redirects): module for module in unique_modules}
        for fut in as_completed(futures):
            module = futures[fut]
            name = module["name"]
            try:
                ok = fut.result()
            except Exception as ex:
                logger.warning("module %s failed: %s", name, ex)
                ok = {"name": name, "detected": False, "evidence": [str(ex)], "status": None, "headers": {}}
            
            normalized = str(ok.get("name") or name)
            normalized = normalized.split("/")[-1].split("\\")[-1]
            if "." in normalized:
                normalized = normalized.split(".")[0]
            normalized = normalized.lower()
            
            ok['name'] = normalized
            results[normalized] = ok
        
        logger.debug("Completed module enumeration: %d results", len(results))
        
        def _filter_overlaps(res_dict: Dict[str, Dict]) -> Dict[str, Dict]:
            detected = [k for k, v in res_dict.items() if v.get("detected")]
            to_remove = set()
            for a in detected:
                for b in detected:
                    if a == b:
                        continue
                    
                    if b.startswith(a) and len(b) > len(a):
                        to_remove.add(a)
                    elif a.startswith(b) and len(a) > len(b):
                        to_remove.add(b)
            if to_remove:
                logger.debug("Filtering overlaps, removing: %s", ", ".join(sorted(to_remove)))
            return {k: v for k, v in res_dict.items() if k not in to_remove}

        results = _filter_overlaps(results)
        return results

def main():
    parser = argparse.ArgumentParser(description="Apache modules detection via HTTP signatures")
    parser.add_argument("--host", default="192.168.1.1", help="target host")
    parser.add_argument("--port", type=int, default=80, help="target port")
    parser.add_argument("--workers", type=int, default=8, help="concurrency level")
    parser.add_argument("--json-output", help="path to store JSON results")
    parser.add_argument("--timeout", type=int, default=5, help="request timeout in seconds")
    parser.add_argument("--scheme", choices=["http", "https"], help="force http/https scheme")
    parser.add_argument("--sni-host", help="host name to use for TLS SNI (useful when targeting IP)")
    parser.add_argument("--host-header", help="value for the Host header (default: same as --host)")
    parser.add_argument("--insecure", action="store_true", help="skip SSL certificate verification (not recommended)")
    parser.add_argument("--no-redirects", action="store_true", help="Do not follow redirects")
    parser.add_argument("--verbose", action="store_true", help="enable debug logs")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s: %(message)s")
    base_url = build_base_url(args.sni_host or args.host, args.port, scheme=args.scheme)

    with requests.Session() as session:
        print(f"{TOOL_NAME} {VERSION} — Developer: {DEVELOPER}")
        
        logger.info("Detecting modules for %s", base_url)
        if args.insecure:
            requests.packages.urllib3.disable_warnings()
        if args.host_header:
            session.headers.update({"Host": args.host_header})
        fingerprint = None
        try:
            fingerprint = collect_fingerprint(session, base_url, timeout=args.timeout, verify=not args.insecure, allow_redirects=not args.no_redirects)
        except requests.exceptions.SSLError as e:
            logger.warning("TLS/SSL error when probing %s: %s", base_url, e)
            logger.info("Try supplying --sni-host <domain> or use a hostname instead of IP to enable SNI, or run 'openssl s_client -connect %s -servername <domain>' to inspect TLS.", base_url)
            fingerprint = {"error": str(e)}
        try:
            results = enumerate_modules(session, base_url, timeout=args.timeout, verify=not args.insecure, allow_redirects=not args.no_redirects, workers=args.workers)
        except requests.exceptions.SSLError as e:
            logger.warning("TLS/SSL error during enumeration: %s", e)
            logger.info("If targeting an IP address, try --sni-host or a domain name to fix SNI-based issues.")
            results = {"error": str(e)}
        
        detected_list = [r.get("name") for r in results.values() if r.get("detected")]
        if detected_list:
            logger.info("Detected modules (%d): %s", len(detected_list), ", ".join(detected_list))
            for name, data in results.items():
                if data.get("detected"):
                    logger.info(" - %s (evidence: %s)", name, ", ".join(data.get("evidence", [])) or "headers")
        else:
            logger.info("No modules detected")
        if args.json_output:
            payload = {"host": base_url, "fingerprint": fingerprint, "results": results, "detected": detected_list}
            with open(args.json_output, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, ensure_ascii=False)
            logger.info("Saved JSON results to %s", args.json_output)


if __name__ == "__main__":
    main()
