import json
import os
import asyncio
import re
import logging
from typing import Dict, List, Optional, Tuple, Any, Mapping
from dataclasses import dataclass
import hashlib
import random

logger = logging.getLogger(__name__)

@dataclass
class BackendSignature:
    name: str
    technology: str
    version_patterns: List[Dict]
    detection_rules: List[Dict]
    confidence_threshold: float
    validation_endpoints: List[str]


class BackendIdentifier:

    def __init__(self, signature_dir: str = "core/profiler/signatures") -> None:
        self.signatures: Dict[str, BackendSignature] = self._load_signatures(signature_dir)
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.user_agents: List[str] = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        ]

    def _load_signatures(self, signature_dir: str) -> Dict[str, BackendSignature]:
        signatures: Dict[str, BackendSignature] = {}
        backend_files = ["backend_signatures.json"]

        for file_name in backend_files:
            file_path = os.path.join(signature_dir, file_name)
            if not os.path.exists(file_path):
                logger.warning(f"Backend signature file not found: {file_path}")
                continue

            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for sig_data in data:
                        signature = BackendSignature(
                            name=sig_data["name"],
                            technology=sig_data["technology"],
                            version_patterns=sig_data.get("version_patterns", []),
                            detection_rules=sig_data.get("detection_rules", []),
                            confidence_threshold=float(sig_data["confidence_threshold"]),
                            validation_endpoints=sig_data.get("validation_endpoints", []),
                        )
                        signatures[signature.name] = signature
            except (json.JSONDecodeError, OSError, KeyError, TypeError, ValueError) as e:
                logger.error(f"Failed to load backend signature file {file_path}: {e}")

        return signatures

    async def identify(self, target_url: str, http_client) -> Dict[str, Dict[str, Any]]:
        cache_key = hashlib.md5(target_url.encode("utf-8", errors="ignore")).hexdigest()
        if cache_key in self.cache:
            return self.cache[cache_key]

        results: Dict[str, Dict[str, Any]] = {}

        try:
            headers = {"User-Agent": random.choice(self.user_agents)}
            resp = await self._safe_get(http_client, target_url, headers=headers, timeout=12)

            if not resp:
                logger.debug(f"Initial request failed for {target_url}")
                self.cache[cache_key] = results
                return results

            status_code, hdrs, body = await self._normalize_response(resp)

            for backend_name, signature in self.signatures.items():
                confidence, version, evidence = await self._check_backend(
                    signature=signature,
                    headers=hdrs,
                    content=body,
                    status_code=status_code,
                    target_url=target_url,
                    http_client=http_client,
                )
                if confidence >= signature.confidence_threshold:
                    results[backend_name] = {
                        "confidence": round(confidence, 2),
                        "version": version,
                        "technology": signature.technology,
                        "evidence": evidence,
                    }

            if not results:
                results = await self._try_validation_endpoints(target_url, http_client)

            self.cache[cache_key] = results
            return results

        except Exception as e:
            logger.error(f"Backend identification failed for {target_url}: {e}")
            return results

    async def _check_backend(self, signature: BackendSignature, headers: Mapping[str, str], content: str, status_code: int, target_url: str, http_client, ) -> Tuple[float, Optional[str], List[str]]:
        max_confidence = 0.0
        version: Optional[str] = None
        evidence: List[str] = []
        
        for rule in signature.detection_rules or []:
            rule_conf, rule_ev = self._check_rule(rule, headers, content, status_code)
            if rule_conf > 0:
                max_confidence = max(max_confidence, rule_conf)
                evidence.extend(rule_ev)

        if max_confidence >= 0.3 and (signature.version_patterns or signature.validation_endpoints):
            v, v_evidence = await self._detect_version(signature, headers, content, target_url, http_client)
            if v:
                version = v
            evidence.extend(v_evidence)

        return max_confidence, version, evidence

    def _check_rule(self, rule: Dict, headers: Mapping[str, str], content: str, status_code: int, ) -> Tuple[float, List[str]]:
        rtype = str(rule.get("type", "")).lower().strip()
        if not rtype:
            return 0.0, []

        confidence = float(rule.get("confidence", 0.0))
        pattern = rule.get("pattern")
        evidence: List[str] = []

        hdrs = {str(k).lower(): str(v) for k, v in dict(headers or {}).items()}
        text = content or ""

        try:
            if rtype == "header":
                hname = str(rule.get("field", "")).lower()
                if not hname:
                    return 0.0, []
                if hname in hdrs:
                    hval = hdrs[hname]
                    if pattern and self._safe_search(pattern, hval):
                        evidence.append(f"Header {hname}: {hval}")
                        return confidence, evidence

            elif rtype == "content":
                if pattern and self._safe_search(pattern, text):
                    evidence.append(f"Content matched: /{pattern}/i")
                    return confidence, evidence

            elif rtype == "status_code":
                code = int(rule.get("code", -1))
                if code == status_code:
                    evidence.append(f"Status code: {status_code}")
                    return confidence, evidence

            elif rtype == "cookie":
                cname = str(rule.get("field", "")).lower()
                sc = hdrs.get("set-cookie", "")
                if cname and cname in sc.lower():
                    evidence.append(f"Cookie present: {cname}")
                    return confidence, evidence

            elif rtype == "meta_tag":
                field_name = str(rule.get("field", ""))
                if not field_name or not pattern:
                    return 0.0, []
                meta_pattern = rf'<meta[^>]*name=["\']{re.escape(field_name)}["\'][^>]*content=["\']([^"\']*)["\']'
                m = re.search(meta_pattern, text, re.IGNORECASE)
                if m and self._safe_search(pattern, m.group(1)):
                    evidence.append(f"Meta {field_name}: {m.group(1)}")
                    return confidence, evidence

        except Exception as e:
            logger.debug(f"Rule evaluation error ({rtype}): {e}")

        return 0.0, []

    async def _detect_version(self, signature: BackendSignature, headers: Mapping[str, str], content: str, target_url: str, http_client, ) -> Tuple[Optional[str], List[str]]:
        hdrs = {str(k).lower(): str(v) for k, v in dict(headers or {}).items()}
        text = content or ""
        evidence: List[str] = []

        for pat in signature.version_patterns or []:
            try:
                if "header" in pat:
                    hname = str(pat["header"]).lower()
                    if hname in hdrs:
                        m = self._safe_search(pat.get("pattern"), hdrs[hname], return_match=True)
                        if m:
                            v = m.group(1) if m.lastindex else m.group(0)
                            evidence.append(f"Version from header {hname}: {v}")
                            return v, evidence

                if "content" in pat:
                    m = self._safe_search(pat.get("pattern"), text, return_match=True)
                    if m:
                        v = m.group(1) if m.lastindex else m.group(0)
                        evidence.append(f"Version from content: {v}")
                        return v, evidence

                if "endpoint" in pat:
                    test_url = f"{target_url.rstrip('/')}/{str(pat['endpoint']).lstrip('/')}"
                    resp = await self._safe_get(http_client, test_url, timeout=8)
                    if not resp:
                        continue
                    status_code, ehdrs, ebody = await self._normalize_response(resp)
                    if status_code == 200:
                        m = self._safe_search(pat.get("pattern"), ebody, return_match=True)
                        if m:
                            v = m.group(1) if m.lastindex else m.group(0)
                            evidence.append(f"Version from endpoint {pat['endpoint']}: {v}")
                            return v, evidence

            except Exception as e:
                logger.debug(f"Version detection error for pattern {pat}: {e}")
                continue

        return None, evidence

    async def _try_validation_endpoints(self, target_url: str, http_client) -> Dict[str, Dict[str, Any]]:
        results: Dict[str, Dict[str, Any]] = {}

        for backend_name, signature in self.signatures.items():
            for endpoint in signature.validation_endpoints or []:
                try:
                    test_url = f"{target_url.rstrip('/')}/{str(endpoint).lstrip('/')}"
                    resp = await self._safe_get(http_client, test_url, timeout=8)
                    if not resp:
                        continue

                    status_code, hdrs, body = await self._normalize_response(resp)
                    if status_code != 200:
                        continue

                    confidence, _, evidence = await self._check_backend(
                        signature=signature,
                        headers=hdrs,
                        content=body,
                        status_code=status_code,
                        target_url=target_url,
                        http_client=http_client,
                    )

                    if confidence >= signature.confidence_threshold:
                        results[backend_name] = {
                            "confidence": round(confidence, 2),
                            "version": None,
                            "technology": signature.technology,
                            "evidence": evidence,
                        }
                        break  

                except Exception as e:
                    logger.debug(f"Validation endpoint test failed for {backend_name} @ {endpoint}: {e}")
                    continue

        return results

    async def _safe_get(self, http_client, url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 12):
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

    async def _normalize_response(self, resp) -> Tuple[int, Dict[str, str], str]:
        status = getattr(resp, "status_code", None)
        if status is None:
            status = getattr(resp, "status", None)
        if status is None:
            status = 0

        raw_headers = getattr(resp, "headers", {}) or {}
        try:
            headers = {str(k).lower(): str(v) for k, v in dict(raw_headers).items()}
        except Exception:
            headers = {}
            try:
                for k in raw_headers.keys():
                    headers[str(k).lower()] = str(raw_headers.get(k))
            except Exception:
                headers = {}

        body_text: str = ""
        txt_attr = getattr(resp, "text", None)
        if isinstance(txt_attr, str):
            body_text = txt_attr
        else:
            try:
                if callable(txt_attr):
                    maybe = txt_attr()
                    if asyncio.iscoroutine(maybe):
                        body_text = await maybe
                    else:
                        body_text = str(maybe) if maybe is not None else ""
                else:
                    body_text = ""
            except Exception:
                body_text = ""

        return int(status), headers, body_text

    def _safe_search(self, pattern: Optional[str], text: str, *, return_match: bool = False):
        if not pattern:
            return None if return_match else False
        try:
            m = re.search(pattern, text, re.IGNORECASE)
            return m if return_match else (m is not None)
        except re.error as e:
            logger.debug(f"Invalid regex '{pattern}': {e}")
            return None if return_match else False
