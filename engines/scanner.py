from __future__ import annotations
import asyncio
import logging
import time
import random
import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse

try:
    import ssdeep 
except Exception:
    ssdeep = None

from core.profiler.waf_detection import WAFDetector
from core.profiler.backend_identifier import BackendIdentifier
from core.profiler.protocol_analyzer import ProtocolAnalyzer
from core.pathnuke import PathNukeEngine
from core.header_forge import HeaderForgeEngine
from core.protocol_decompiler import ProtocolDecompilerEngine
from core.ai_core import AICore
from utils.http_client import AsyncHTTPClient
from engines.validator import TripleValidator

logger = logging.getLogger(__name__)

@dataclass
class ResponseFingerprint:
    status: int
    length: int
    cookie_fp: str
    headers_fp: str
    header_entropy: float
    body_fuzzy: Optional[str] 
    t: float

    @staticmethod
    def _entropy(s: str) -> float:
        if not s:
            return 0.0
        from math import log2
        freq: Dict[str, int] = {}
        for ch in s:
            freq[ch] = freq.get(ch, 0) + 1
        n = len(s)
        return -sum((c / n) * log2(c / n) for c in freq.values())

    @classmethod
    def from_http(cls, response: Any) -> "ResponseFingerprint":
        status = int(getattr(response, "status_code", 0) or 0)
        text = getattr(response, "text", "") or ""
        headers = getattr(response, "headers", {}) or {}
        set_cookie = headers.get("Set-Cookie", "") or headers.get("set-cookie", "") or ""
        header_str = ";".join(f"{k.lower()}={str(v)[:128]}" for k, v in headers.items())
        length = len(text)
        cookie_fp = hashlib.md5(set_cookie.encode("utf-8", errors="ignore")).hexdigest()
        headers_fp = hashlib.md5(header_str.encode("utf-8", errors="ignore")).hexdigest()
        body_fuzzy = ssdeep.hash(text) if ssdeep else None
        entropy = cls._entropy(header_str)

        return cls(
            status=status,
            length=length,
            cookie_fp=cookie_fp,
            headers_fp=headers_fp,
            header_entropy=entropy,
            body_fuzzy=body_fuzzy,
            t=time.time(),
        )

    def delta(self, other: "ResponseFingerprint") -> Dict[str, Any]:
        out = {
            "status_diff": self.status != other.status,
            "length_diff_ratio": (
                abs(self.length - other.length) / max(1, max(self.length, other.length))
            ),
            "cookie_changed": self.cookie_fp != other.cookie_fp,
            "headers_changed": self.headers_fp != other.headers_fp,
            "entropy_delta": abs(self.header_entropy - other.header_entropy),
            "fuzzy_distance": None,
        }
        if ssdeep and self.body_fuzzy and other.body_fuzzy:
            try:
                sim = ssdeep.compare(self.body_fuzzy, other.body_fuzzy)
                out["fuzzy_distance"] = 1.0 - (sim / 100.0)
            except Exception:
                out["fuzzy_distance"] = None
        return out

class NuclearScanner:
    def __init__(self, config: Dict):
        self.config = {
            "max_concurrency": 8,
            "ai_enabled": True,
            "ai_attempts": 5,
            "seed": 1337,
            "persona": {},            
            "replay_attempts": 2,   
            "replay_delay_ms": 150,  
            **(config or {}),
        }

        self.http_client = AsyncHTTPClient(self.config)
        self.ai_core = AICore()
        self.validator = TripleValidator()
        self.waf_detector = WAFDetector()
        self.backend_identifier = BackendIdentifier()
        self.protocol_analyzer = ProtocolAnalyzer()
        self.pathnuke_engine = PathNukeEngine(self.waf_detector, self.backend_identifier)
        self.header_forge_engine = HeaderForgeEngine()
        self.protocol_decompiler_engine = ProtocolDecompilerEngine()
        self.results: List[Dict] = []
        self.target_profile: Dict[str, Any] = {}
        self._baseline_fingerprint: Optional[ResponseFingerprint] = None
        self._set_seed(int(self.config.get("seed", 1337)))
        try:
            self.ai_core.set_seed(int(self.config.get("seed", 1337)))
        except Exception:
            pass
        persona = self.config.get("persona") or {}
        if persona:
            self.ai_core.set_persona(persona)
        self._sem = asyncio.Semaphore(int(self.config.get("max_concurrency", 8)))

    async def scan(self, target_url: str) -> List[Dict]:
        logger.info(f"Starting scan: {target_url}")
        try:
            await self._capture_baseline(target_url)
            await self._profile_target(target_url)
            self.ai_core.initialize_rl_agent(self._mk_target_profile_for_ai())
            bypass_results = await self._execute_attacks(target_url)
            validated = await self._validate_results_with_pipeline(target_url, bypass_results)

            await self._generate_reports(validated)

            logger.info(f"Scan complete: {target_url} — valid bypasses: {len(validated)}")
            return validated
        except Exception as e:
            logger.error(f"Scan failed for {target_url}: {e}")
            return []

    def _set_seed(self, seed: int) -> None:
        random.seed(seed)
        try:
            import numpy as np
            np.random.seed(seed)
        except Exception:
            pass

    async def _capture_baseline(self, target_url: str) -> None:
        try:
            resp = await self.http_client.get(target_url, timeout=12)
            self._baseline_fingerprint = ResponseFingerprint.from_http(resp)
            self.target_profile["baseline"] = {
                "status": self._baseline_fingerprint.status,
                "length": self._baseline_fingerprint.length,
                "headers_fp": self._baseline_fingerprint.headers_fp,
            }
        except Exception as e:
            logger.debug(f"Baseline request failed: {e}")
            self._baseline_fingerprint = None

    async def _profile_target(self, target_url: str) -> None:
        logger.info("Profiling target...")

        waf_results = await self.waf_detector.detect(target_url, self.http_client)
        backend_results = await self.backend_identifier.identify(target_url, self.http_client)
        protocol_results = await self.protocol_analyzer.analyze(target_url, self.http_client)

        self.target_profile = {
            "url": target_url,
            "waf": waf_results,
            "backend": backend_results,
            "protocol": protocol_results,
        }
        logger.info(f"Target profile: {self.target_profile}")
        if self.config.get("persona"):
            self.target_profile["persona"] = self.config["persona"]

    def _mk_target_profile_for_ai(self) -> Dict[str, Any]:
        waf_type = next(iter(self.target_profile.get("waf", {}).keys()), "")
        backend_name = next(iter(self.target_profile.get("backend", {}).keys()), "")
        return {
            "waf_detected": bool(self.target_profile.get("waf")),
            "waf_type": waf_type,
            "backend": backend_name,
            "http_versions": self.target_profile.get("protocol", {}).get("http_versions", []),
        }

    async def _execute_attacks(self, target_url: str) -> List[Dict]:
        results: List[Dict] = []
        if self._should_execute_path_attacks():
            logger.info("Executing path-based attacks...")
            try:
                path_results = await self.pathnuke_engine.execute_attacks(target_url, self.http_client)
                results.extend(path_results)
            except Exception as e:
                logger.error(f"Path attacks failed: {e}")

        if self._should_execute_header_attacks():
            logger.info("Executing header-based attacks...")
            try:
                orig_headers = self._get_original_headers()
                header_results = await self.header_forge_engine.execute_attacks(
                    target_url, orig_headers, self.http_client
                )
                results.extend(header_results)
            except Exception as e:
                logger.error(f"Header attacks failed: {e}")

        if self._should_execute_protocol_attacks():
            logger.info("Executing protocol-level attacks...")
            try:
                proto_results = await self.protocol_decompiler_engine.execute_attacks(target_url, self.http_client)
                results.extend(proto_results)
            except Exception as e:
                logger.error(f"Protocol attacks failed: {e}")

        if self.config.get("ai_enabled", True):
            logger.info("Executing AI-guided attempts...")
            ai_results = await self._execute_ai_attacks(target_url)
            results.extend(ai_results)

        return results

    async def _execute_ai_attacks(self, target_url: str) -> List[Dict]:
        results: List[Dict] = []
        history: List[Dict] = []
        attempts = int(self.config.get("ai_attempts", 5))

        for i in range(attempts):
            try:
                action = self.ai_core.get_next_action(history, self._mk_target_profile_for_ai())
                result = await self._execute_ai_action(target_url, action)
                if result:
                    history.append(result)
                    state = self.ai_core.environment.get_state(history[:-1], self._mk_target_profile_for_ai())
                    reward = self.ai_core.environment.calculate_reward(result, history[-2] if len(history) > 1 else None)
                    next_state = self.ai_core.environment.get_state(history, self._mk_target_profile_for_ai())
                    self.ai_core.learn_from_experience(state, 0, reward, next_state, False)

                    if reward > 0:
                        results.append(result)
            except Exception as e:
                logger.error(f"AI-guided attempt {i+1}/{attempts} failed: {e}")

        return results

    async def _execute_ai_action(self, target_url: str, action: Dict) -> Optional[Dict]:
        action_type = (action or {}).get("type", "")
        try:
            if action_type == "path_trim":
                parsed = urlparse(target_url)
                base_path = parsed.path or "/"
                trim_engine = self.pathnuke_engine.engines["trim"]
                payloads = await trim_engine.generate_payloads(target_url, base_path)
                test_results = await trim_engine.test_payloads(target_url, payloads[:6], self.http_client)
                return test_results[0] if test_results else None

            if action_type == "header_injection":
                headers = self._get_original_headers()
                header_name = action.get("header", "X-Forwarded-For")
                header_value = action.get("value", "127.0.0.1")
                headers[header_name] = header_value
                resp = await self.http_client.get(target_url, headers=headers, timeout=12)
                return {
                    "technique": "header_injection",
                    "url": target_url,
                    "header": header_name,
                    "value": header_value,
                    "status_code": getattr(resp, "status_code", 0),
                    "response_size": len(getattr(resp, "text", "") or ""),
                }

            if action_type == "method_override":
                method = action.get("method", "POST")
                resp = await self.http_client.request(method, target_url, timeout=12)
                return {
                    "technique": "method_override",
                    "url": target_url,
                    "method": method,
                    "status_code": getattr(resp, "status_code", 0),
                    "response_size": len(getattr(resp, "text", "") or ""),
                }

            if action_type == "protocol_attack":
                proto = action.get("protocol", "")
                proto_results = await self.protocol_decompiler_engine.execute_attacks(target_url, self.http_client)
                if proto:
                    proto_results = [r for r in proto_results if r.get("protocol", "").lower().startswith(proto.lower())]
                return proto_results[0] if proto_results else None

        except Exception as e:
            logger.error(f"AI action execution failed ({action_type}): {e}")
        return None

    async def _validate_results_with_pipeline(self, target_url: str, raw_results: List[Dict]) -> List[Dict]:
        validated: List[Dict] = []
        for res in raw_results:
            try:
                ok = await self.validator.validate(res, self.http_client)
                if not ok:
                    continue

                decision_pass = await self._decision_pipeline_check(target_url, res)
                if not decision_pass:
                    continue

                replay_ok = await self._persona_replay_check(res)
                res["replay_confirmed"] = bool(replay_ok)

                validated.append(res)
            except Exception as e:
                logger.debug(f"Validation failed for result {res.get('url', 'n/a')}: {e}")
        return validated

    async def _decision_pipeline_check(self, target_url: str, res: Dict) -> bool:
        if not self._baseline_fingerprint:
            return True 

        url = res.get("url", target_url)
        try:
            cand_resp = await self.http_client.get(url, timeout=12)
        except Exception:
            return False

        cand_fp = ResponseFingerprint.from_http(cand_resp)
        delta = cand_fp.delta(self._baseline_fingerprint)

        score = 0
        if delta["status_diff"] or delta["length_diff_ratio"] > 0.15:
            score += 1
        if delta["cookie_changed"]:
            score += 1
        if delta["headers_changed"] or delta["entropy_delta"] > 0.5:
            score += 1
        if delta["fuzzy_distance"] is not None and delta["fuzzy_distance"] > 0.20:
            score += 1

        res["decision_signals"] = delta
        res["decision_score"] = score
        return score >= 2

    async def _persona_replay_check(self, res: Dict) -> bool:
        url = res.get("url")
        if not url:
            return True

        attempts = int(self.config.get("replay_attempts", 2))
        hits = 0
        for i in range(attempts):
            try:
                await asyncio.sleep(max(0, float(self.config.get("replay_delay_ms", 150))) / 1000.0)
                headers = self._get_original_headers()
                headers["User-Agent"] = self._jitter_ua(headers.get("User-Agent", ""))

                r = await self.http_client.get(url, headers=headers, timeout=10)
                if int(getattr(r, "status_code", 0)) < 400:
                    hits += 1
            except Exception:
                continue

        res["replay_hits"] = hits
        res["replay_attempts"] = attempts
        return hits >= max(1, attempts // 2 + (attempts % 2))

    async def _generate_reports(self, validated_results: List[Dict]) -> None:
        for r in validated_results:
            r.setdefault("persona", self.config.get("persona", {}))
            logger.info(f"VALIDATED: {r}")

    def _should_execute_path_attacks(self) -> bool:
        return bool(self.config.get("path_attacks", True))

    def _should_execute_header_attacks(self) -> bool:
        waf = self.target_profile.get("waf", {})
        backend = (self.target_profile.get("backend", {}) or {})
        backend_name = " ".join(backend.keys()).lower()
        return bool(waf) or any(b in backend_name for b in ["nginx", "apache", "iis"])

    def _should_execute_protocol_attacks(self) -> bool:
        proto = self.target_profile.get("protocol", {}) or {}
        versions = proto.get("http_versions", []) or []
        return any(v.strip().upper() == "HTTP/0.9" for v in versions)

    def _get_original_headers(self) -> Dict[str, str]:
        return {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close",
        }

    @staticmethod
    def _jitter_ua(ua: str) -> str:
        if not ua:
            return ua
        parts = ua.split()
        if parts and random.random() < 0.5:
            parts[-1] = parts[-1] + f".{random.randint(1, 9)}"
        return " ".join(parts)
