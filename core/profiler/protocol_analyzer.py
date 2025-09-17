import asyncio
import re
import random
import logging
import time
import ssl as sslmod
from typing import Dict, List, Optional, Tuple, Any, Mapping
from urllib.parse import urlparse
import hashlib

logger = logging.getLogger(__name__)

class Budget:
    def __init__(self, max_raw_ops: int = 12):
        self.max_raw_ops = max_raw_ops
        self.used = 0

    def take(self, n: int = 1) -> bool:
        if self.used + n > self.max_raw_ops:
            return False
        self.used += n
        return True


class Proof:
    __slots__ = ("name", "persona_id", "req_bytes", "resp_head", "status", "timing_ms")
    def __init__(self, name: str, persona_id: str, req_bytes: bytes, resp_head: str, status: int, timing_ms: float):
        self.name = name
        self.persona_id = persona_id
        self.req_bytes = req_bytes[:2048]      
        self.resp_head = resp_head[:1024]     
        self.status = status
        self.timing_ms = timing_ms


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

class ProtocolAnalyzer:

    def __init__(self) -> None:
        self.supported_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"]
        self.cache: Dict[str, Dict[str, Any]] = {}
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
        self.RAW_READ_LIMIT = 65536
        self.RAW_TIMEOUT = 6.0
        
    async def analyze(self, target_url: str, http_client, include_proofs: bool = False) -> Dict[str, Any]:
        cache_key = hashlib.md5(target_url.encode("utf-8", errors="ignore")).hexdigest()
        if cache_key in self.cache and not include_proofs:
            return self.cache[cache_key]

        budget = Budget(max_raw_ops=12) 
        proofs: List[Proof] = []

        http_versions = await self._test_http_versions(target_url, http_client, proofs, budget)
        method_override = await self._test_method_override(target_url, http_client)
        chunked = await self._test_chunked_encoding(target_url, http_client, proofs, budget)
        malformed = await self._test_malformed_headers(target_url, http_client, proofs, budget)
        proto_vulns = await self._test_protocol_vulnerabilities(target_url, http_client)
        smuggling = await self._test_request_smuggling(target_url, http_client, proofs, budget)

        analysis_results = {
            "http_versions": http_versions,
            "method_override_support": method_override,
            "chunked_encoding": chunked,
            "malformed_header_handling": malformed,
            "protocol_vulnerabilities": proto_vulns,
            "request_smuggling": smuggling,
        }
        if include_proofs:
            analysis_results["proofs"] = [
                {
                    "name": p.name,
                    "persona_id": p.persona_id,
                    "status": p.status,
                    "timing_ms": round(p.timing_ms, 2),
                    "resp_head": p.resp_head,
                    "req_sample_b64": _b64sample(p.req_bytes),
                }
                for p in proofs
            ]

        self.cache[cache_key] = analysis_results
        return analysis_results

    async def _test_http_versions(self, target_url: str, http_client, proofs: List[Proof], budget: Budget) -> List[str]:
        supported: List[str] = []
        try:
            ua = random.choice(self.user_agents)
            t0 = time.perf_counter()
            resp = await self._safe_get(http_client, target_url, headers={"User-Agent": ua[1]}, timeout=10)
            elapsed = (time.perf_counter() - t0) * 1000.0
            if resp:
                status, hdrs, _ = await self._normalize_response(resp)
                version_attr = getattr(resp, "http_version", None)
                alt_svc = _lower_headers(hdrs).get("alt-svc", "")
                if version_attr:
                    if "2" in str(version_attr):
                        supported.append("HTTP/2")
                    elif "1.1" in str(version_attr):
                        supported.append("HTTP/1.1")
                    elif "1.0" in str(version_attr):
                        supported.append("HTTP/1.0")
                else:
                    if status > 0:
                        supported.append("HTTP/1.1")
                if "h3" in alt_svc:
                    supported.append("HTTP/3 (advertised)")
                if "h2" in alt_svc and "HTTP/2" not in supported:
                    supported.append("HTTP/2 (advertised)")

                head_line = f"status={status}; alt-svc={alt_svc[:120]}"
                proofs.append(Proof("http_version_probe", ua[0], b"", head_line, status, elapsed))

        except Exception as e:
            logger.debug(f"HTTP version check (client) failed: {e}")

        if budget.take(1):
            ok_09 = await self._test_http09_raw(target_url, proofs)
            if ok_09 and "HTTP/0.9" not in supported:
                supported.append("HTTP/0.9")

        seen = set()
        filtered = []
        for v in supported:
            if v not in seen:
                filtered.append(v)
                seen.add(v)
        return filtered

    async def _test_http09_raw(self, target_url: str, proofs: List[Proof]) -> bool:
        try:
            parsed = urlparse(target_url)
            host = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            path = parsed.path or "/"

            ssl_context = None
            if parsed.scheme == "https":
                ssl_context = sslmod.create_default_context()
            t0 = time.perf_counter()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=host, port=port, ssl=ssl_context, server_hostname=(host if ssl_context else None)
                ),
                timeout=self.RAW_TIMEOUT,
            )
            req = f"GET {path}\r\n".encode("ascii", "ignore")
            writer.write(req)
            await writer.drain()

            data = await asyncio.wait_for(reader.read(self.RAW_READ_LIMIT), timeout=self.RAW_TIMEOUT)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

            elapsed = (time.perf_counter() - t0) * 1000.0
            head = data[:64].decode(errors="ignore")
            looks_http10 = head.startswith("HTTP/")
            ok = (len(data) > 0) and (not looks_http10)
            proofs.append(Proof("http09_raw", "raw", req, head, 0 if not ok else 200, elapsed))
            return ok
        except Exception as e:
            logger.debug(f"HTTP/0.9 raw probe failed: {e}")
            return False

    async def _test_method_override(self, target_url: str, http_client) -> Dict[str, bool]:
        override_headers = [
            ("X-HTTP-Method-Override", "PUT"),
            ("X-HTTP-Method", "PUT"),
            ("X-Method-Override", "PUT"),
            ("HTTP-Method-Override", "PUT"),
        ]
        results: Dict[str, bool] = {}
        for hname, hval in override_headers:
            try:
                ua = random.choice(self.user_agents)[1]
                resp = await self._safe_post(
                    http_client,
                    target_url,
                    headers={"User-Agent": ua, hname: hval},
                    data={"test": "data"},
                    timeout=10,
                )
                if not resp:
                    results[hname] = False
                    continue
                status, _, text = await self._normalize_response(resp)
                results[hname] = status not in (400, 405, 501)
            except Exception as e:
                logger.debug(f"Method override test failed for {hname}: {e}")
                results[hname] = False
        return results

    async def _test_chunked_encoding(self, target_url: str, http_client, proofs: List[Proof], budget: Budget) -> Dict[str, Any]:
        result = {"supported": False, "vulnerabilities": []}
        parsed = urlparse(target_url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"

        if not budget.take(2):
            return result
        
        try:
            ua = random.choice(self.user_agents)
            req = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {ua[1]}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Connection: close\r\n\r\n"
                "7\r\n"
                "test=ok\r\n"
                "0\r\n\r\n"
            ).encode("ascii", "ignore")
            status, head = await self._raw_roundtrip(parsed.scheme, host, port, req)
            result["supported"] = status not in (400, 411, 501, 505)
            proofs.append(Proof("chunked_wellformed", ua[0], req, head, status, 0.0))
        except Exception as e:
            logger.debug(f"Chunked support probe failed: {e}")

        if result["supported"]:
            try:
                ua = random.choice(self.user_agents)
                req_bad = (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: {ua[1]}\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Connection: close\r\n\r\n"
                    "5\r\n"     
                    "hello\r\n"
                    "3\r\n"     
                    "world\r\n"
                    "0\r\n\r\n"
                ).encode("ascii", "ignore")
                status2, head2 = await self._raw_roundtrip(parsed.scheme, host, port, req_bad)
                if status2 and status2 < 400:
                    result["vulnerabilities"].append("chunked_encoding_bypass")
                proofs.append(Proof("chunked_malformed", ua[0], req_bad, head2, status2, 0.0))
            except Exception as e:
                logger.debug(f"Chunked malformed probe failed: {e}")

        return result

    async def _test_malformed_headers(self, target_url: str, http_client, proofs: List[Proof], budget: Budget) -> Dict[str, bool]:
        parsed = urlparse(target_url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"

        tests = {
            "line_folding": "Header: Value\r\n Continued",
            "non_standard_separator": "Header Value",
            "unicode_in_headers": "Header: Valüe",
            "null_byte_in_header": "Header: Value\0WithNull",
            "multiple_spaces": "Header: Value   With   Spaces",
            "leading_trailing_spaces": "Header:   Value   ",
        }

        results: Dict[str, bool] = {}
        if not budget.take(len(tests)):
            for k in tests.keys():
                results[k] = False
            return results

        for name, raw_header in tests.items():
            try:
                ua = random.choice(self.user_agents)
                req = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: {ua[1]}\r\n"
                    f"{raw_header}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("latin-1", "ignore")
                status, head = await self._raw_roundtrip(parsed.scheme, host, port, req)
                results[name] = bool(status and status < 500)
                proofs.append(Proof(f"malformed_header_{name}", ua[0], req, head, status, 0.0))
            except Exception as e:
                logger.debug(f"Malformed header test '{name}' failed: {e}")
                results[name] = False

        return results

    async def _test_protocol_vulnerabilities(self, target_url: str, http_client) -> Dict[str, bool]:
        return {
            "response_splitting": await self._test_response_splitting(target_url, http_client),
            "host_header_injection": await self._test_host_header_injection(target_url, http_client),
            "http_parameter_pollution": await self._test_parameter_pollution(target_url, http_client),
        }

    async def _test_response_splitting(self, target_url: str, http_client) -> bool:
        try:
            crlf_payload = "%0d%0aX-Injected-Header: test%0d%0a"
            test_url = f"{target_url.rstrip('?')}{'&' if '?' in target_url else '?'}param={crlf_payload}"
            resp = await self._safe_get(http_client, test_url, timeout=8)
            if not resp:
                return False
            _, hdrs, _ = await self._normalize_response(resp)
            return "x-injected-header" in _lower_headers(hdrs)
        except Exception:
            return False

    async def _test_host_header_injection(self, target_url: str, http_client) -> bool:
        try:
            malicious = "evil.com"
            ua = random.choice(self.user_agents)[1]
            resp = await self._safe_get(http_client, target_url, headers={"User-Agent": ua, "Host": malicious}, timeout=8)
            if not resp:
                return False
            _, _, text = await self._normalize_response(resp)
            return malicious in (text or "")
        except Exception:
            return False

    async def _test_parameter_pollution(self, target_url: str, http_client) -> bool:
        try:
            sep = "&" if "?" in target_url else "?"
            url_multi = f"{target_url}{sep}id=1&id=2&id=3"
            url_single = f"{target_url}{sep}id=1"
            r1 = await self._safe_get(http_client, url_multi, timeout=8)
            r2 = await self._safe_get(http_client, url_single, timeout=8)
            if not (r1 and r2):
                return False
            _, _, t1 = await self._normalize_response(r1)
            _, _, t2 = await self._normalize_response(r2)
            return (t1 or "") != (t2 or "")
        except Exception:
            return False

    async def _test_request_smuggling(self, target_url: str, http_client, proofs: List[Proof], budget: Budget) -> Dict[str, Any]:
        parsed = urlparse(target_url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"

        techniques: Dict[str, bool] = {"cl_te": False, "te_cl": False, "te_te": False}
        if not budget.take(3):
            return {"detected": False, "techniques": techniques, "note": "budget_exhausted"}

        try:
            ua = random.choice(self.user_agents)
            req_cl_te = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {ua[1]}\r\n"
                f"Content-Length: 6\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Connection: close\r\n\r\n"
                "0\r\n\r\n"
                "GARBAG"
            ).encode("ascii", "ignore")
            s1, h1 = await self._raw_roundtrip(parsed.scheme, host, port, req_cl_te)
            techniques["cl_te"] = bool(s1 and s1 in (200, 400, 408, 413, 425, 426, 500, 502))
        except Exception:
            pass
        try:
            ua = random.choice(self.user_agents)
            req_te_cl = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {ua[1]}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Content-Length: 4\r\n"
                f"Connection: close\r\n\r\n"
                "5\r\nhello\r\n0\r\n\r\n"
            ).encode("ascii", "ignore")
            s2, h2 = await self._raw_roundtrip(parsed.scheme, host, port, req_te_cl)
            techniques["te_cl"] = bool(s2 and s2 in (200, 400, 408, 413, 425, 426, 500, 502))
        except Exception:
            pass
        try:
            ua = random.choice(self.user_agents)
            req_te_te = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {ua[1]}\r\n"
                f"Transfer-Encoding: chunked, chunked\r\n"
                f"Connection: close\r\n\r\n"
                "5\r\nhello\r\n0\r\n\r\n"
            ).encode("ascii", "ignore")
            s3, h3 = await self._raw_roundtrip(parsed.scheme, host, port, req_te_te)
            techniques["te_te"] = bool(s3 and s3 in (200, 400, 408, 413, 425, 426, 500, 502))
        except Exception:
            pass

        detected = any(techniques.values())
        return {"detected": detected, "techniques": techniques}

    async def _safe_get(self, http_client, url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 10):
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

    async def _safe_post(
        self, http_client, url: str, headers: Optional[Dict[str, str]] = None, data: Any = None, timeout: int = 12
    ):
        try:
            return await http_client.post(url, headers=headers or {}, data=data, timeout=timeout, follow_redirects=True)
        except TypeError:
            try:
                return await http_client.post(url, headers=headers or {}, data=data, timeout=timeout)
            except Exception as e:
                logger.debug(f"_safe_post failed for {url}: {e}")
                return None
        except Exception as e:
            logger.debug(f"_safe_post failed for {url}: {e}")
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

    async def _raw_roundtrip(self, scheme: str, host: str, port: int, req_bytes: bytes) -> Tuple[int, str]:
        ssl_ctx = None
        if scheme == "https":
            ssl_ctx = sslmod.create_default_context()

        t0 = time.perf_counter()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host=host, port=port, ssl=ssl_ctx, server_hostname=(host if ssl_ctx else None)),
            timeout=self.RAW_TIMEOUT,
        )
        writer.write(req_bytes)
        await writer.drain()

        data = await asyncio.wait_for(reader.read(self.RAW_READ_LIMIT), timeout=self.RAW_TIMEOUT)
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        elapsed = (time.perf_counter() - t0) * 1000.0
        head = data[:80].decode(errors="ignore")
        status = 0
        m = re.match(r"HTTP/\d\.\d\s+(\d{3})", head)
        if m:
            try:
                status = int(m.group(1))
            except Exception:
                status = 0

        return status, head

def _b64sample(b: bytes) -> str:
    try:
        import base64
        return base64.b64encode(b[:512]).decode()
    except Exception:
        return ""
