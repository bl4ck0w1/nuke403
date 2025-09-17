import asyncio
import logging
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse
from .trim_inconsistency import TrimInconsistencyEngine
from .path_smuggling import PathSmugglingEngine
from .matrix_parameters import MatrixParameterEngine
from .dotless_ip import DotlessIPEngine

logger = logging.getLogger(__name__)
class PathNukeEngine:
    def __init__(
        self,
        waf_detector,
        backend_identifier,
        *,
        enabled: Optional[List[str]] = None,
        max_concurrency: int = 3
    ):
        self.engines: Dict[str, Any] = {
            "trim": TrimInconsistencyEngine(waf_detector, backend_identifier),
            "smuggling": PathSmugglingEngine(waf_detector, backend_identifier),
            "matrix": MatrixParameterEngine(waf_detector, backend_identifier),
            "dotless": DotlessIPEngine(),
        }
        if enabled is not None:
            self.engines = {k: v for k, v in self.engines.items() if k in set(enabled)}

        self.max_concurrency = max_concurrency
        
    async def execute_attacks(self, target_url: str, http_client) -> List[Dict[str, Any]]:
        parsed = urlparse(target_url)
        base_path = parsed.path or "/"

        sem = asyncio.Semaphore(self.max_concurrency)

        async def _run_engine(name: str, engine: Any) -> List[Dict[str, Any]]:
            try:
                async with sem:
                    if name == "dotless":
                        payloads: List[str] = await engine.generate_payloads(target_url, http_client)
                        results: List[Dict[str, Any]] = await engine.test_payloads(
                            target_url, payloads, http_client
                        )
                    else:
                        payloads = await engine.generate_payloads(target_url, base_path, http_client)
                        results = await engine.test_payloads(
                            target_url, base_path, payloads, http_client
                        )
                    logger.info(f"[PathNuke:{name}] completed with {len(results)} finding(s).")
                    return results
            except Exception as e:
                logger.error(f"[PathNuke:{name}] engine failed: {e}")
                return []

        tasks = [asyncio.create_task(_run_engine(n, e)) for n, e in self.engines.items()]
        results_nested = await asyncio.gather(*tasks, return_exceptions=True)

        merged: List[Dict[str, Any]] = []
        for r in results_nested:
            if isinstance(r, Exception):
                logger.debug(f"[PathNuke] task error: {r}")
                continue
            merged.extend(r or [])

        seen_keys = set()
        deduped: List[Dict[str, Any]] = []
        for item in merged:
            key = (
                item.get("technique", ""),
                item.get("url", ""),
                item.get("payload", ""),
                item.get("status_code", 0),
            )
            if key not in seen_keys:
                seen_keys.add(key)
                deduped.append(item)

        deduped.sort(key=lambda x: (-(200 <= x.get("status_code", 0) < 300), x.get("technique", ""), x.get("url", "")))
        logger.info(f"[PathNuke] Total findings: {len(deduped)} (from {len(self.engines)} engines)")
        return deduped
