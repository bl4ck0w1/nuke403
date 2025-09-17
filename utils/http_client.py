from __future__ import annotations
import asyncio
import hashlib
import logging
import random
import ssl
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, Union, List, Deque
from collections import deque, defaultdict
from urllib.parse import urlparse
import aiohttp

try:
    from aiohttp_socks import ProxyConnector
except Exception: 
    ProxyConnector = None  

logger = logging.getLogger(__name__)

@dataclass
class HTTPResponse:
    url: str
    status_code: int
    headers: Dict[str, str]
    text: str
    body: bytes
    response_time: float 

    @property
    def response_time_ms(self) -> float:
        return self.response_time * 1000.0

def _build_ssl_context(verify_ssl: bool, fingerprint_evasion: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    ctx.options |= ssl.OP_NO_SSLv2
    ctx.options |= ssl.OP_NO_SSLv3
    ctx.options |= ssl.OP_NO_TLSv1
    ctx.options |= ssl.OP_NO_TLSv1_1
    ctx.options |= ssl.OP_NO_COMPRESSION

    if fingerprint_evasion:
        ciphers = [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "ECDHE-RSA-CHACHA20-POLY1305",
        ]
        random.shuffle(ciphers)
        try:
            ctx.set_ciphers(":".join(ciphers[:6]))
        except Exception:
            pass
        try:
            ctx.set_ecdh_curve("prime256v1") 
        except Exception:
            pass

    return ctx

class AsyncHTTPClient:
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        *,
        max_connections: int = 100,
        max_connections_per_host: int = 10,
        max_retries: int = 3,
        retry_delay: float = 0.75,
        timeout: float = 30.0,
        rate_limit: Optional[int] = None,  
        burst_capacity: int = 5,
        proxy: Optional[str] = None,
        proxy_failover: Optional[List[str]] = None,
        user_agent: str = "Nuke403/1.0 (+https://example.invalid)",
        tls_fingerprint_evasion: bool = True,
        verify_ssl: bool = True,
        enable_caching: bool = True,):
        cfg = config or {}
        self.max_connections = int(cfg.get("max_connections", max_connections))
        self.max_connections_per_host = int(cfg.get("max_connections_per_host", max_connections_per_host))
        self.max_retries = int(cfg.get("max_retries", max_retries))
        self.retry_delay = float(cfg.get("retry_delay", retry_delay))
        self.default_timeout = float(cfg.get("timeout", timeout))
        self.rate_limit = cfg.get("rate_limit", rate_limit)
        self.burst_capacity = int(cfg.get("burst_capacity", burst_capacity))
        self.proxy = cfg.get("proxy", proxy)
        self.proxy_failover = cfg.get("proxy_failover", proxy_failover or [])
        self.user_agent = cfg.get("user_agent", user_agent)
        self.tls_fingerprint_evasion = bool(cfg.get("tls_fingerprint_evasion", tls_fingerprint_evasion))
        self.verify_ssl = bool(cfg.get("verify_ssl", verify_ssl))
        self.enable_caching = bool(cfg.get("enable_caching", enable_caching))
        self._req_times: Deque[float] = deque()
        self._burst_tokens = self.burst_capacity
        self._last_refill = time.monotonic()
        self._fp_cache: Dict[str, str] = {}
        self._resp_cache: Dict[str, HTTPResponse] = {}
        self._cache_hits = 0
        self._cache_misses = 0
        self._stats = {
            "start_time": time.time(),
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "retry_events": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
        }
        self._pool_state = defaultdict(lambda: {"active": 0, "errors": 0})
        self._ssl_context = _build_ssl_context(self.verify_ssl, self.tls_fingerprint_evasion)
        self._session: Optional[aiohttp.ClientSession] = None
        self._connector = self._build_connector()
        self._http_proxy_for_request = self.proxy if (self.proxy and self.proxy.startswith(("http://", "https://"))) else None
        self._supports_per_request_http_version = False 

    async def __aenter__(self) -> "AsyncHTTPClient":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.close()

    def _build_connector(self) -> aiohttp.BaseConnector:
        if self.proxy and self.proxy.startswith(("socks4://", "socks5://")) and ProxyConnector:
            return ProxyConnector.from_url(
                self.proxy,
                limit=self.max_connections,
                limit_per_host=self.max_connections_per_host,
                ssl=self._ssl_context,
                rdns=True,
            )
        return aiohttp.TCPConnector(
            limit=self.max_connections,
            limit_per_host=self.max_connections_per_host,
            ssl=self._ssl_context,
            force_close=False,
            enable_cleanup_closed=True,
        )

    async def start(self) -> None:
        if self._session and not self._session.closed:
            return
        self._session = aiohttp.ClientSession(
            connector=self._connector,
            timeout=aiohttp.ClientTimeout(total=self.default_timeout),
            headers={"User-Agent": self.user_agent},
            trust_env=False,
            raise_for_status=False,
        )

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None
        uptime = time.time() - self._stats["start_time"]
        logger.info(
            "HTTP Client: uptime=%.1fs total=%d ok=%d fail=%d retries=%d rx=%.2fMB tx=%.2fMB cache(hit=%d miss=%d)",
            uptime,
            self._stats["total_requests"],
            self._stats["successful_requests"],
            self._stats["failed_requests"],
            self._stats["retry_events"],
            self._stats["bytes_received"] / 1024 / 1024,
            self._stats["bytes_sent"] / 1024 / 1024,
            self._cache_hits,
            self._cache_misses,
        )

    async def _rate_limit(self) -> None:
        if not self.rate_limit:
            return
        now = time.monotonic()
        if now - self._last_refill >= 1.0:
            add = int((now - self._last_refill) * self.rate_limit)
            self._burst_tokens = min(self.burst_capacity, self._burst_tokens + max(add, 0))
            self._last_refill = now
        while self._req_times and self._req_times[0] <= now - 1.0:
            self._req_times.popleft()
        if len(self._req_times) >= self.rate_limit and self._burst_tokens <= 0:
            sleep_for = 1.0 - (now - self._req_times[0])
            if sleep_for > 0:
                await asyncio.sleep(sleep_for)
        elif len(self._req_times) >= self.rate_limit and self._burst_tokens > 0:
            self._burst_tokens -= 1
        self._req_times.append(time.monotonic())

    def _request_fingerprint(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]],
        data: Optional[Union[str, bytes]],
        allow_redirects: bool,
    ) -> str:
        key = f"{method.upper()}|{url}|{int(bool(allow_redirects))}"
        if headers:
            key += "|" + hashlib.md5(repr(sorted((k.lower(), str(v)) for k, v in headers.items())).encode()).hexdigest()
        if data is not None:
            if isinstance(data, str):
                data = data.encode()
            key += "|" + hashlib.md5(data).hexdigest()
        if key in self._fp_cache:
            return self._fp_cache[key]
        fp = hashlib.sha256(key.encode()).hexdigest()
        if self.enable_caching:
            self._fp_cache[key] = fp
            if len(self._fp_cache) > 20000:
                self._fp_cache.pop(next(iter(self._fp_cache)))
        return fp

    def _should_retry(self, e: Exception, attempt: int) -> bool:
        if attempt >= self.max_retries:
            return False
        retryable = (
            isinstance(e, (aiohttp.ClientConnectorError, aiohttp.ServerDisconnectedError, aiohttp.ClientOSError))
            or isinstance(e, (asyncio.TimeoutError,))
        )
        if retryable:
            return True
        if isinstance(e, aiohttp.ClientResponseError):
            if e.status == 429 or (500 <= e.status < 600):
                return True
        if isinstance(e, ssl.SSLError):
            return True
        return False

    async def _retry_delay(self, attempt: int) -> float:
        base = self.retry_delay * (2 ** attempt)
        return base + random.uniform(0, base * 0.15)

    async def _rotate_proxy(self) -> None:
        if not self.proxy_failover:
            return
        self.proxy_failover = list(self.proxy_failover)  
        self.proxy_failover.append(self.proxy_failover.pop(0))
        self.proxy = self.proxy_failover[0]
        if self.proxy.startswith(("socks4://", "socks5://")) and ProxyConnector:
            self._connector = self._build_connector()
            if self._session and not self._session.closed:
                await self._session.close()
            self._session = None
            await self.start()
        logger.info("Rotated proxy to: %s", self.proxy)

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Union[str, bytes]] = None,
        allow_redirects: bool = True,
        fingerprint: Optional[str] = None,
        skip_duplicate_check: bool = False,
        cache_response: bool = False,
        read_response: bool = True,
        timeout: Optional[float] = None,
        http_version: Optional[str] = None,  
        proxy: Optional[str] = None, 
        **_ignored: Any,
    ) -> HTTPResponse:
        await self.start()
        await self._rate_limit()
        self._stats["total_requests"] += 1
        req_headers = {**(headers or {})}
        req_headers.setdefault("User-Agent", self.user_agent)
        if data is not None:
            self._stats["bytes_sent"] += len(data if isinstance(data, (bytes, bytearray)) else str(data).encode())

        fp = fingerprint or self._request_fingerprint(method, url, req_headers, data, allow_redirects)
        if self.enable_caching and not skip_duplicate_check and fp in self._resp_cache:
            self._cache_hits += 1
            return self._resp_cache[fp]
        self._cache_misses += 1

        req_timeout = aiohttp.ClientTimeout(total=timeout or self.default_timeout)

        effective_http_proxy = proxy or self._http_proxy_for_request

        last_exc: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            try:
                t0 = time.perf_counter()
                async with self._session.request(  
                    method.upper(),
                    url,
                    headers=req_headers,
                    data=data,
                    allow_redirects=allow_redirects,
                    timeout=req_timeout,
                    proxy=effective_http_proxy,
                ) as resp:
                    body = await resp.read() if read_response else b""
                    elapsed = time.perf_counter() - t0
                    self._stats["bytes_received"] += len(body)
                    self._stats["successful_requests"] += 1

                    hdrs = {k: v for k, v in resp.headers.items()}
                    text = ""
                    if body:
                        try:
                            text = body.decode(resp.charset or "utf-8", errors="replace")
                        except Exception:
                            text = body.decode("utf-8", errors="replace")

                    normalized = HTTPResponse(
                        url=str(resp.url),
                        status_code=int(resp.status),
                        headers=hdrs,
                        text=text,
                        body=body,
                        response_time=elapsed,
                    )

                    if self.enable_caching and cache_response:
                        self._resp_cache[fp] = normalized
                        if len(self._resp_cache) > 2000:
                            self._resp_cache.pop(next(iter(self._resp_cache)))

                    host = urlparse(url).hostname or ""
                    self._pool_state[host]["active"] += 1

                    return normalized

            except Exception as e:
                last_exc = e
                self._stats["failed_requests"] += 1
                host = urlparse(url).hostname or ""
                self._pool_state[host]["errors"] += 1

                if not self._should_retry(e, attempt):
                    logger.debug("Request failed (no retry): %s %s -> %s", method, url, repr(e))
                    break

                self._stats["retry_events"] += 1
                delay = await self._retry_delay(attempt)
                logger.debug("Request failed (attempt %d/%d). Retrying in %.2fs: %s",
                             attempt + 1, self.max_retries + 1, delay, repr(e))

                if isinstance(e, (aiohttp.ClientConnectorError, aiohttp.ServerDisconnectedError)) and self.proxy_failover:
                    await self._rotate_proxy()

                await asyncio.sleep(delay)

        raise last_exc if last_exc else RuntimeError("Request failed without exception")

    async def get(self, url: str, **kwargs) -> HTTPResponse:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, data: Optional[Union[bytes, str]] = None, **kwargs) -> HTTPResponse:
        return await self.request("POST", url, data=data, **kwargs)

    async def head(self, url: str, **kwargs) -> HTTPResponse:
        return await self.request("HEAD", url, **kwargs)

    async def put(self, url: str, data: Optional[Union[bytes, str]] = None, **kwargs) -> HTTPResponse:
        return await self.request("PUT", url, data=data, **kwargs)

    async def delete(self, url: str, **kwargs) -> HTTPResponse:
        return await self.request("DELETE", url, **kwargs)

    async def options(self, url: str, **kwargs) -> HTTPResponse:
        return await self.request("OPTIONS", url, **kwargs)

    async def patch(self, url: str, data: Optional[Union[bytes, str]] = None, **kwargs) -> HTTPResponse:
        return await self.request("PATCH", url, data=data, **kwargs)

    async def trace(self, url: str, **kwargs) -> HTTPResponse:
        return await self.request("TRACE", url, **kwargs)

    async def send_raw(self, raw_request: bytes, host: str, port: int = 443, use_ssl: bool = True) -> HTTPResponse:
        await self.start()
        await self._rate_limit()
        self._stats["total_requests"] += 1
        self._stats["bytes_sent"] += len(raw_request)

        ssl_ctx = self._ssl_context if use_ssl else None
        t0 = time.perf_counter()
        reader, writer = await asyncio.open_connection(host, port, ssl=ssl_ctx)
        try:
            writer.write(raw_request)
            await writer.drain()

            chunks: List[bytes] = []
            while True:
                try:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=10.0)
                except asyncio.TimeoutError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
            raw = b"".join(chunks)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        elapsed = time.perf_counter() - t0
        self._stats["bytes_received"] += len(raw)

        text = raw.decode("utf-8", errors="replace") if raw else ""
        status_code = 0
        if text.startswith("HTTP/"):
            try:
                line = text.split("\r\n", 1)[0]
                status_code = int(line.split(" ", 2)[1])
            except Exception:
                status_code = 0

        return HTTPResponse(
            url=f"{'https' if use_ssl else 'http'}://{host}:{port}",
            status_code=status_code,
            headers={}, 
            text=text,
            body=raw,
            response_time=elapsed,
        )

    def get_stats(self) -> Dict[str, Any]:
        uptime = time.time() - self._stats["start_time"]
        rps = self._stats["total_requests"] / uptime if uptime else 0.0
        return {
            "uptime_seconds": uptime,
            "total_requests": self._stats["total_requests"],
            "successful_requests": self._stats["successful_requests"],
            "failed_requests": self._stats["failed_requests"],
            "retry_events": self._stats["retry_events"],
            "rps": rps,
            "bytes_sent_mb": self._stats["bytes_sent"] / 1024 / 1024,
            "bytes_received_mb": self._stats["bytes_received"] / 1024 / 1024,
            "cache_hits": self._cache_hits,
            "cache_misses": self._cache_misses,
            "cache_hit_ratio": (self._cache_hits / (self._cache_hits + self._cache_misses))
            if (self._cache_hits + self._cache_misses) else 0.0,
            "pool": dict(self._pool_state),
        }

    def clear_cache(self) -> None:
        self._fp_cache.clear()
        self._resp_cache.clear()
        self._cache_hits = 0
        self._cache_misses = 0

http_client = AsyncHTTPClient()
