import asyncio
import hashlib
import logging
import re
import ssl
from typing import List, Dict, Any, Optional, Mapping, Tuple
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger(__name__)


class HostInheritanceEngine:
    def __init__(self, *, max_concurrency: int = 8, body_cap_bytes: int = 512 * 1024):
        self.max_concurrency = max_concurrency
        self.body_cap_bytes = body_cap_bytes

        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
        ]

        self.safe_hosts = [
            "nuke403.invalid",
            "nuke403.example",
            "cdn-origin.example",
            "cachepoison.invalid",
        ]

        self.unicode_dot_hosts = [
            "nuke403。example", 
            "nuke403｡example", 
        ]

        self.obf_hosts = [
            "nuke403.example.",        
            "nuke403.example:80",      
            "nuke403.example:443",     
            "nuke403.example\t",      
            " nuke403.example",       
        ]

        self.forward_headers = [
            "X-Forwarded-Host",
            "X-Forwarded-Server",
            "X-HTTP-Host-Override",
            "X-Original-Host",
            "X-Host",
            "Forwarded", 
        ]

    async def generate_payloads(self, target_url: str, base_headers: Optional[Dict[str, str]] = None, http_client: Any = None, ) -> List[Dict[str, Any]]:
        parsed = urlparse(target_url)
        orig_host = parsed.hostname or ""
        path = parsed.path or "/"

        bh = dict(base_headers or {})
        if "User-Agent" not in bh:
            bh["User-Agent"] = self.user_agents[0]
        if "Accept" not in bh:
            bh["Accept"] = "*/*"
            
        payloads: List[Dict[str, Any]] = []

        def add_std(label: str, headers: Dict[str, str]):
            merged = {**bh, **headers}
            payloads.append({"label": label, "headers": merged, "headers_list": None, "use_raw": False})

        def add_raw(label: str, header_pairs: List[Tuple[str, str]]):
            payloads.append({"label": label, "headers": None, "headers_list": header_pairs, "use_raw": True})

        for h in self.safe_hosts:
            add_std("x-forwarded-host", {"X-Forwarded-Host": h})
            add_std("x-forwarded-server", {"X-Forwarded-Server": h})
            add_std("x-http-host-override", {"X-HTTP-Host-Override": h})
            add_std("x-original-host", {"X-Original-Host": h})
            add_std("x-host", {"X-Host": h})
            add_std("forwarded-host", {"Forwarded": f'host="{h}"'})
            add_std("forwarded-host-proto-https", {"Forwarded": f'host="{h}"; proto="https"'})
            add_std("forwarded-host-proto-http", {"Forwarded": f'host="{h}"; proto="http"'})

        for h in self.unicode_dot_hosts:
            add_std("x-forwarded-host-unicode-dot", {"X-Forwarded-Host": h})

        for h in self.obf_hosts:
            add_std("x-forwarded-host-obf", {"X-Forwarded-Host": h})

        for h in (self.safe_hosts + self.obf_hosts + self.unicode_dot_hosts):
            add_raw("host-override", [("Host", h)])

        for h in self.safe_hosts:
            add_raw("host-duplicate-first-target", [("Host", h), ("Host", orig_host or h)])
            add_raw("host-duplicate-last-target", [("Host", orig_host or h), ("Host", h)])

        for h in self.safe_hosts:
            add_raw("host+xfh", [("Host", orig_host or h), ("X-Forwarded-Host", h)])

        logger.info(f"[HostInheritance] Prepared {len(payloads)} payloads for {orig_host}{path}")
        return payloads

    async def test_payloads(self, target_url: str, payloads: List[Dict[str, Any]], http_client: Any,) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        parsed = urlparse(target_url)
        path_q = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
        baseline = await self._client_snapshot(http_client, target_url, headers={"User-Agent": self.user_agents[1], "Accept": "*/*"})

        sem = asyncio.Semaphore(self.max_concurrency)

        async def run_one(p: Dict[str, Any]) -> Optional[Dict[str, Any]]:
            label = p["label"]
            try:
                async with sem:
                    if p["use_raw"]:
                        snap = await self._raw_snapshot(parsed, path_q, headers_list=p["headers_list"] or [])
                    else:
                        snap = await self._client_snapshot(http_client, target_url, headers=p["headers"] or {})
                if not snap or not baseline:
                    return None

                verdict, reason = self._is_host_inherited(snap, baseline, p)
                if verdict:
                    return {
                        "technique": "host_inheritance",
                        "label": label,
                        "status_code": snap["status"],
                        "response_size": len(snap["body"]),
                        "proof": {
                            "location": snap["headers"].get("location", ""),
                            "set_cookie": snap["headers"].get("set-cookie", "")[:256],
                            "body_md5": snap["body_md5"],
                            "cookie_fp": snap["cookie_fp"],
                            "headers_sample": dict(list(snap["headers"].items())[:10]),
                            "reason": reason,
                        },
                        "payload": p if p["use_raw"] else {"headers": p["headers"]},
                    }
            except Exception as e:
                logger.debug(f"[HostInheritance] {label} failed: {e}")
                return None
            return None

        tasks = [asyncio.create_task(run_one(p)) for p in payloads]
        for out in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(out, Exception):
                logger.debug(f"[HostInheritance] task error: {out}")
                continue
            if out:
                results.append(out)

        return results

    def _is_host_inherited(self, snap: Dict[str, Any], baseline: Dict[str, Any], payload: Dict[str, Any]) -> Tuple[bool, str]:
        status = snap["status"]
        h = snap["headers"]
        body = snap["body"]
        lbody = body.lower()
        block_indicators = ["access denied", "forbidden", "unauthorized", "blocked", "captcha"]
        if any(b in lbody for b in block_indicators):
            return False, ""

        injected_host = self._extract_injected_host(payload)

        if 300 <= status < 400:
            loc = h.get("location", "") or ""
            if injected_host and injected_host.lower() in loc.lower():
                return True, "redirect_location_contains_injected_host"

        if 200 <= status < 300 and injected_host:
            reflected = (injected_host.lower() in lbody) or any(
                injected_host.lower() in (h.get(k, "") or "").lower()
                for k in ("content-location", "link", "referer", "x-accel-redirect")
            )
            if reflected:
                if snap["body_md5"] != baseline["body_md5"] or snap["cookie_fp"] != baseline["cookie_fp"]:
                    return True, "content_reflects_injected_host_with_delta"

        if (snap["cookie_fp"] != baseline["cookie_fp"]) and (snap["body_md5"] != baseline["body_md5"]):
            if status != baseline["status"] or h.get("server", "") != baseline["headers"].get("server", ""):
                return True, "cookie_and_body_delta_with_status_or_server_change"

        return False, ""

    def _extract_injected_host(self, payload: Dict[str, Any]) -> Optional[str]:
        if payload.get("use_raw"):
            hdrs = payload.get("headers_list") or []
            vals = [v for (k, v) in hdrs if k.lower() == "host" or k.lower().startswith("x-forwarded-host")]
            return vals[-1] if vals else None
        else:
            hdrs = payload.get("headers") or {}
            for k in ("Host", "X-Forwarded-Host", "X-Host", "X-Original-Host", "X-Forwarded-Server"):
                if k in hdrs:
                    return hdrs[k]
            fwd = hdrs.get("Forwarded")
            if fwd:
                m = re.search(r'host\s*=\s*"?(?P<h>[^;,"\s]+)"?', fwd, re.I)
                if m:
                    return m.group("h")
        return None

    async def _client_snapshot(self, http_client, url: str, headers: Optional[Dict[str, str]] = None) -> Optional[Dict[str, Any]]:
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
                "cookie_fp": self._cookie_fingerprint(h.get("set-cookie", "")),
            }
        except Exception as e:
            logger.debug(f"[HostInheritance] client snapshot failed: {e}")
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

    async def _raw_snapshot(self, parsed, path: str, headers_list: List[Tuple[str, str]], timeout: int = 12,) -> Optional[Dict[str, Any]]:
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        try:
            if parsed.scheme == "https":
                ctx = ssl.create_default_context()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host=host, port=port, ssl=ctx, server_hostname=host),
                    timeout=timeout,
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host=host, port=port),
                    timeout=timeout,
                )

            lines = [f"GET {path or '/'} HTTP/1.1"]
            if not any(k.lower() == "host" for (k, _) in headers_list):
                lines.append(f"Host: {host}")

            for k, v in headers_list:
                lines.append(f"{k}: {v}")

            lines.append("Connection: close")
            lines.append("") 
            raw = ("\r\n".join(lines) + "\r\n").encode("latin-1", errors="ignore")

            writer.write(raw)
            await writer.drain()

            raw_headers = await self._read_until(reader, b"\r\n\r\n", timeout)
            if raw_headers is None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return None

            status, headers_map = self._parse_headers(raw_headers.decode("latin-1", errors="ignore"))
            body = await self._read_body(reader, headers_map, timeout)

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            h_lower = {k.lower(): v for k, v in headers_map.items()}
            body_s = body
            return {
                "status": status,
                "headers": h_lower,
                "body": body_s,
                "body_md5": hashlib.md5(body_s.encode("utf-8", errors="ignore")).hexdigest(),
                "cookie_fp": self._cookie_fingerprint(h_lower.get("set-cookie", "")),
            }

        except Exception as e:
            logger.debug(f"[HostInheritance] raw snapshot error: {e}")
            return None

    async def _read_until(self, reader: asyncio.StreamReader, sep: bytes, timeout: int) -> Optional[bytes]:
        try:
            buf = b""
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                if not chunk:
                    break
                buf += chunk
                i = buf.find(sep)
                if i >= 0:
                    return buf[: i + len(sep)]
                if len(buf) > 256 * 1024:
                    return None
            return None
        except Exception:
            return None

    def _parse_headers(self, header_blob: str) -> Tuple[int, Dict[str, str]]:
        lines = header_blob.split("\r\n")
        status_line = lines[0] if lines else "HTTP/1.1 000"
        m = re.search(r"\s(\d{3})\s?", status_line)
        code = int(m.group(1)) if m else 0
        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            k, v = line.split(":", 1)
            headers[k.strip()] = v.lstrip()
        return code, headers

    async def _read_body(self, reader: asyncio.StreamReader, headers: Dict[str, str], timeout: int) -> str:
        try:
            if headers.get("Transfer-Encoding", "").lower().startswith("chunked"):
                return await self._read_chunked(reader, timeout)

            length = headers.get("Content-Length")
            if length and length.isdigit():
                n = min(int(length), self.body_cap_bytes)
                data = await asyncio.wait_for(reader.readexactly(n), timeout=timeout)
                return data.decode(self._guess_encoding(headers), errors="ignore")

            data = b""
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                if not chunk:
                    break
                data += chunk
                if len(data) > self.body_cap_bytes:
                    break
            return data.decode(self._guess_encoding(headers), errors="ignore")
        except Exception:
            return ""

    async def _read_chunked(self, reader: asyncio.StreamReader, timeout: int) -> str:
        data = b""
        try:
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=timeout)
                if not line:
                    break
                line = line.strip()
                m = re.match(rb"^([0-9A-Fa-f]+)", line)
                if not m:
                    break
                size = int(m.group(1), 16)
                if size == 0:
                    await asyncio.wait_for(reader.readline(), timeout=timeout)  
                    break
                chunk = await asyncio.wait_for(reader.readexactly(size), timeout=timeout)
                data += chunk
                await asyncio.wait_for(reader.readline(), timeout=timeout)  
            return data.decode("utf-8", errors="ignore")
        except Exception:
            return data.decode("utf-8", errors="ignore")

    def _guess_encoding(self, headers: Dict[str, str]) -> str:
        ct = headers.get("Content-Type", "")
        m = re.search(r"charset=([A-Za-z0-9_\-]+)", ct, re.I)
        return m.group(1) if m else "utf-8"


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
