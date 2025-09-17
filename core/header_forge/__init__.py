import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple
from .line_folding import LineFoldingEngine
from .cache_poisoning import CachePoisoningEngine
from .host_inheritance import HostInheritanceEngine

logger = logging.getLogger(__name__)

class HeaderForgeEngine:
    def __init__(self, *, enabled: Optional[List[str]] = None, max_concurrency: int = 3,) -> None:
        engines: Dict[str, Any] = {
            "line_folding": LineFoldingEngine(),
            "cache_poisoning": CachePoisoningEngine(),
            "host_inheritance": HostInheritanceEngine(),
        }
        if enabled is not None:
            keep = set(enabled)
            engines = {k: v for k, v in engines.items() if k in keep}

        self.engines = engines
        self.max_concurrency = max_concurrency

    async def execute_attacks(self, target_url: str, original_headers: Dict[str, str], http_client: Any,) -> List[Dict[str, Any]]:
        base_headers = {k: v for k, v in (original_headers or {}).items() if k.lower() != "host"}
        sem = asyncio.Semaphore(self.max_concurrency)
        async def _run_engine(name: str, engine: Any) -> List[Dict[str, Any]]:
            try:
                async with sem:
                    payloads = await engine.generate_payloads(target_url, base_headers, http_client)
                async with sem:
                    results = await engine.test_payloads(target_url, payloads, http_client)
                logger.info(f"[HeaderForge:{name}] {len(results)} finding(s).")
                return results
            except Exception as e:
                logger.error(f"[HeaderForge:{name}] engine failed: {e}")
                return []

        tasks = [asyncio.create_task(_run_engine(n, e)) for n, e in self.engines.items()]
        nested = await asyncio.gather(*tasks, return_exceptions=True)

        merged: List[Dict[str, Any]] = []
        for r in nested:
            if isinstance(r, Exception):
                logger.debug(f"[HeaderForge] task error: {r}")
                continue
            merged.extend(r or [])

        seen = set()
        deduped: List[Dict[str, Any]] = []
        for item in merged:
            key = self._result_key(item)
            if key not in seen:
                seen.add(key)
                deduped.append(item)

        def _score(it: Dict[str, Any]) -> Tuple[int, str, str]:
            code = int(it.get("status_code") or it.get("cached_status") or 0)
            good = 1 if (200 <= code < 300) else 0
            technique = str(it.get("technique", ""))
            anchor = str(
                it.get("url")
                or it.get("victim_url")
                or it.get("poison_url")
                or it.get("label", "")
            )
            return (-good, technique, anchor)

        deduped.sort(key=_score)
        logger.info(f"[HeaderForge] Total findings: {len(deduped)} from {len(self.engines)} engine(s)")
        return deduped

    def _result_key(self, it: Dict[str, Any]) -> Tuple:
        technique = it.get("technique", "")
        anchor = it.get("url") or it.get("victim_url") or it.get("poison_url") or it.get("label", "")
        status = it.get("status_code") or it.get("cached_status") or 0
        payload_obj = it.get("payload") or it.get("headers") or {}
        payload_fp = self._freeze(payload_obj)
        return (technique, str(anchor), int(status), payload_fp)

    def _freeze(self, obj: Any) -> Tuple:
        if isinstance(obj, dict):
            return tuple((k, self._freeze(v)) for k, v in sorted(obj.items()))
        if isinstance(obj, (list, tuple)):
            return tuple(self._freeze(v) for v in obj)
        return (obj,)
