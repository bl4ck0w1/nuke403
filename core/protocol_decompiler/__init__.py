import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple
from .http09_backchannel import HTTP09BackchannelEngine
from .chunked_encoding import ChunkedEncodingEngine
from .method_override import MethodOverrideEngine

logger = logging.getLogger(__name__)

try:
    import ssdeep  
except Exception: 
    ssdeep = None

class ProtocolDecompilerEngine:
    def __init__(self, *, max_concurrency: int = 5, enable_http09: bool = True, enable_chunked: bool = True, enable_method_override: bool = True,) -> None:
        self.max_concurrency = max_concurrency
        self.enable_http09 = enable_http09
        self.enable_chunked = enable_chunked
        self.enable_method_override = enable_method_override
        self.http09 = HTTP09BackchannelEngine()
        self.chunked = ChunkedEncodingEngine()
        self.method_override = MethodOverrideEngine()

    async def run(self, target_url: str, http_client: Any, *, original_method: str = "POST", ) -> Dict[str, Any]:
        tasks = []
        if self.enable_http09:
            tasks.append(asyncio.create_task(self._run_http09(target_url)))
        if self.enable_chunked:
            tasks.append(asyncio.create_task(self._run_chunked(target_url, http_client)))
        if self.enable_method_override:
            tasks.append(asyncio.create_task(self._run_method_override(target_url, http_client, original_method)))

        results: List[List[Dict[str, Any]]] = await asyncio.gather(*tasks, return_exceptions=True)
        findings: List[Dict[str, Any]] = []
        for res in results:
            if isinstance(res, Exception):
                logger.debug(f"[protocol_decompiler] subtask error: {res}")
                continue
            findings.extend(res or [])

        deduped = self._dedupe(findings)
        summary = self._summarize(deduped)
        clusters = self._cluster(deduped)
        if clusters:
            summary["clusters"] = clusters

        return {"summary": summary, "findings": deduped}

    async def _run_http09(self, target_url: str) -> List[Dict[str, Any]]:
        try:
            out = await self.http09.test_backchannel(target_url)
            normalized: List[Dict[str, Any]] = []
            for it in out or []:
                it = dict(it)
                it.setdefault("technique", "http09_backchannel")
                normalized.append(it)
            logger.info(f"[protocol_decompiler] http09_backchannel findings: {len(normalized)}")
            return normalized
        except Exception as e:
            logger.error(f"[protocol_decompiler] HTTP/0.9 run failed: {e}")
            return []

    async def _run_chunked(self, target_url: str, http_client: Any) -> List[Dict[str, Any]]:
        try:
            payloads = await self.chunked.generate_payloads(target_url, original_data={})
            out = await self.chunked.test_payloads(target_url, payloads, http_client)
            for it in out:
                it.setdefault("technique", "chunked_encoding")
            logger.info(f"[protocol_decompiler] chunked_encoding findings: {len(out)}")
            return out
        except Exception as e:
            logger.error(f"[protocol_decompiler] chunked run failed: {e}")
            return []

    async def _run_method_override(self, target_url: str, http_client: Any, original_method: str ) -> List[Dict[str, Any]]:
        try:
            payloads = await self.method_override.generate_payloads(target_url, original_method)
            out = await self.method_override.test_payloads(target_url, payloads, http_client)
            for it in out:
                it.setdefault("technique", "method_override")
            logger.info(f"[protocol_decompiler] method_override findings: {len(out)}")
            return out
        except Exception as e:
            logger.error(f"[protocol_decompiler] method-override run failed: {e}")
            return []

    def _dedupe(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        out: List[Dict[str, Any]] = []
        for f in findings:
            technique = f.get("technique", "unknown")
            label = f.get("label", "")
            status = f.get("status_code", f.get("status", 0))
            body_md5 = (f.get("proof", {}) or {}).get("body_md5", "")

            if not label:
                comp = (
                    f.get("port", ""),
                    f.get("path", ""),
                    f.get("method", "") or f.get("override_method", "") or f.get("verb", ""),
                    f.get("protocol", ""),
                )
                label = f"{comp}"

            key = (technique, label, status, body_md5)
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out

    def _summarize(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        by_tech: Dict[str, int] = {}
        for f in findings:
            tech = f.get("technique", "unknown")
            by_tech[tech] = by_tech.get(tech, 0) + 1
        return {
            "total_findings": len(findings),
            "by_technique": by_tech,
        }

    def _cluster(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not ssdeep:
            return []
        
        corpus: List[Tuple[int, str]] = []
        bodies: List[str] = []

        for idx, f in enumerate(findings):
            body = ""
            proof = f.get("proof") or {}
            if "first_bytes" in proof:
                body = proof["first_bytes"]
            elif "response_preview" in f:
                body = f.get("response_preview", "")
            if not body:
                continue
            try:
                fh = ssdeep.hash(body)
                corpus.append((idx, fh))
                bodies.append(body)
            except Exception:
                continue

        used = set()
        clusters: List[Dict[str, Any]] = []
        thresh = 85  
        for i, (idx_i, fh_i) in enumerate(corpus):
            if idx_i in used:
                continue
            group = [idx_i]
            used.add(idx_i)
            for j in range(i + 1, len(corpus)):
                idx_j, fh_j = corpus[j]
                if idx_j in used:
                    continue
                try:
                    score = ssdeep.compare(fh_i, fh_j)
                    if score >= thresh:
                        group.append(idx_j)
                        used.add(idx_j)
                except Exception:
                    continue
            if len(group) > 1:
                clusters.append({
                    "size": len(group),
                    "members": [findings[k].get("label") or findings[k].get("technique", "") for k in group],
                    "techniques": list({findings[k].get("technique", "") for k in group}),
                })
        return clusters
