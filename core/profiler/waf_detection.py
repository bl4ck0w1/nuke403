import json
import os
import asyncio
import re
import random
import time
import math
import hashlib
import statistics
from typing import Dict, List, Optional, Any, Tuple, Union, Mapping
from dataclasses import dataclass, field
from urllib.parse import quote
import logging

logger = logging.getLogger(__name__)

try:
    import ssdeep 
    _HAS_SSDEEP = True
except Exception:
    _HAS_SSDEEP = False

@dataclass
class WAFTest:
    type: str  
    category: str  
    path: str  
    pattern: Union[str, List[str]]
    payload: Optional[str] = None
    match: str = "any"  
    score: float = 0.5


@dataclass
class WAFSignature:
    name: str
    vendor: str
    description: str
    confidence_threshold: float
    tests: List[WAFTest]


@dataclass
class NormalizedResponse:
    url: str
    status_code: int
    headers: Dict[str, str]
    text: str
    http_version: Optional[str] = None  
    ja3: Optional[str] = None         
    alpn: Optional[str] = None          
    hops: List[str] = field(default_factory=list)  
    cache_hit: Optional[bool] = None
    timing_ms: float = 0.0
    persona_id: str = ""             
    cookie_fp: str = ""              
    body_len: int = 0
    body_md5: str = ""
    body_ssdeep: Optional[str] = None
    header_entropy: float = 0.0


@dataclass
class ProofArtifact:
    baseline: Optional[NormalizedResponse]
    observed: NormalizedResponse
    signals: Dict[str, Any]  

class WAFDetector:
    def __init__(self, signature_dir: str = "core/profiler/signatures") -> None:
        self.signatures: Dict[str, WAFSignature] = self._load_signatures(signature_dir)

        self.user_agents = [
            ("desktop-chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                               "AppleWebKit/537.36 (KHTML, like Gecko) "
                               "Chrome/124.0.0.0 Safari/537.36"),
            ("desktop-safari", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                               "AppleWebKit/605.1.15 (KHTML, like Gecko) "
                               "Version/14.1.1 Safari/605.1.15"),
            ("desktop-firefox", "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) "
                                "Gecko/20100101 Firefox/122.0"),
        ]
        self.cache: Dict[str, Dict[str, float]] = {}
        self.baselines: Dict[str, NormalizedResponse] = {}
        self.proofs: Dict[str, Dict[str, List[ProofArtifact]]] = {}
        self.timings: Dict[Tuple[str, str], List[float]] = {}

    def _load_signatures(self, signature_dir: str) -> Dict[str, WAFSignature]:
        signatures: Dict[str, WAFSignature] = {}

        consolidated_file = os.path.join(signature_dir, "consolidated_waf_signatures.json")
        if os.path.exists(consolidated_file):
            try:
                with open(consolidated_file, "r", encoding="utf-8") as f:
                    consolidated_data = json.load(f)
                    for _vendor, vendor_signatures in consolidated_data.items():
                        for sig_data in vendor_signatures:
                            signature_key = f"{sig_data['vendor']}_{sig_data['name']}".lower().replace(" ", "_")
                            tests = [WAFTest(**test) for test in sig_data.get("tests", [])]
                            signatures[signature_key] = WAFSignature(
                                name=sig_data["name"],
                                vendor=sig_data["vendor"],
                                description=sig_data.get("description", ""),
                                confidence_threshold=sig_data["confidence_threshold"],
                                tests=tests,
                            )
            except (json.JSONDecodeError, OSError) as e:
                logger.error(f"Failed to load consolidated signature file {consolidated_file}: {e}")

        signature_files = [
            "cloudflare_signatures.json",
            "aws_waf_signatures.json",
            "akamai_signatures.json",
            "nginx_signatures.json",
        ]

        for file_name in signature_files:
            file_path = os.path.join(signature_dir, file_name)
            if not os.path.exists(file_path):
                logger.debug(f"Signature file not found: {file_path}")
                continue

            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for sig_data in data:
                        signature_key = f"{sig_data['vendor']}_{sig_data['name']}".lower().replace(" ", "_")
                        new_tests = [WAFTest(**test) for test in sig_data.get("tests", [])]

                        if signature_key in signatures:
                            existing = signatures[signature_key]
                            combined = existing.tests + [
                                t for t in new_tests if not any(self._tests_equal(t, e) for e in existing.tests)
                            ]
                            signatures[signature_key] = WAFSignature(
                                name=existing.name,
                                vendor=existing.vendor,
                                description=existing.description,
                                confidence_threshold=existing.confidence_threshold,
                                tests=combined,
                            )
                        else:
                            signatures[signature_key] = WAFSignature(
                                name=sig_data["name"],
                                vendor=sig_data["vendor"],
                                description=sig_data.get("description", ""),
                                confidence_threshold=sig_data["confidence_threshold"],
                                tests=new_tests,
                            )
            except (json.JSONDecodeError, OSError) as e:
                logger.error(f"Failed to load signature file {file_path}: {e}")

        logger.info(f"Loaded {len(signatures)} WAF signatures")
        return signatures

    @staticmethod
    def _tests_equal(t1: WAFTest, t2: WAFTest) -> bool:
        return (
            t1.type == t2.type
            and t1.category == t2.category
            and t1.path == t2.path
            and t1.pattern == t2.pattern
        )

    async def detect(self, target_url: str, http_client, include_proofs: bool = False) -> Union[Dict[str, float], Tuple[Dict[str, float], Dict[str, List[ProofArtifact]]]]:
        if target_url in self.cache and not include_proofs:
            return self.cache[target_url]

        detection_results: Dict[str, float] = {}
        proofs_for_target: Dict[str, List[ProofArtifact]] = {}

        logger.info(f"Starting WAF detection for {target_url}")

        baseline = await self._make_request(target_url, http_client)
        if baseline:
            self.baselines[target_url] = baseline
            self._record_timing(target_url, baseline.persona_id, baseline.timing_ms)

        passive_results, passive_proofs = await self._run_passive_tests(baseline)
        detection_results.update(passive_results)
        self._merge_proofs(proofs_for_target, passive_proofs)

        if not any(conf > 0.8 for conf in detection_results.values()):
            active_results, active_proofs = await self._run_active_tests(target_url, http_client)
            for waf_name, conf in active_results.items():
                detection_results[waf_name] = max(detection_results.get(waf_name, 0.0), conf)
            self._merge_proofs(proofs_for_target, active_proofs)

        filtered: Dict[str, float] = {}
        for waf, conf in detection_results.items():
            if waf not in self.signatures:
                continue
            downrank = self._edge_downrank_factor(proofs_for_target.get(waf, []))
            eff_conf = round(max(0.0, conf * downrank), 2)
            if eff_conf >= self.signatures[waf].confidence_threshold:
                filtered[waf] = eff_conf

        self.cache[target_url] = filtered
        self.proofs[target_url] = proofs_for_target
        logger.info(f"WAF detection completed. Results: {filtered}")

        if include_proofs:
            return filtered, proofs_for_target
        return filtered

    async def _make_request( self, url: str, http_client, headers: Optional[Dict[str, str]] = None, payload: Optional[str] = None, persona_id: Optional[str] = None, ) -> Optional[NormalizedResponse]:
        persona = random.choice(self.user_agents)
        pid, ua = persona if persona_id is None else (persona_id, next((ua for p, ua in self.user_agents if p == persona_id), ua))

        req_headers: Dict[str, str] = {"User-Agent": ua}
        if headers:
            req_headers.update(headers)

        test_url = f"{url.rstrip('/')}/{quote(payload)}" if payload else url

        start = time.perf_counter()
        try:
            resp = await http_client.get(test_url, headers=req_headers, timeout=12)
            elapsed_ms = (time.perf_counter() - start) * 1000.0

            headers_map: Mapping[str, str] = getattr(resp, "headers", {}) or {}
            lowered = {str(k).lower(): str(v) for k, v in dict(headers_map).items()}

            status = getattr(resp, "status_code", None)
            if status is None:
                status = getattr(resp, "status", None)
            if status is None:
                status = 0

            body_text: str = ""
            if isinstance(getattr(resp, "text", None), str):
                body_text = resp.text
            else:
                text_coro = getattr(resp, "text", None)
                if callable(text_coro):
                    maybe = text_coro()
                    if asyncio.iscoroutine(maybe):
                        body_text = await maybe
                    else:
                        body_text = str(maybe) if maybe is not None else ""
                else:
                    body_text = ""

            hops: List[str] = []
            hist = getattr(resp, "history", None)
            if hist:
                try:
                    for h in hist:
                        hops.append(getattr(h, "url", "") or "")
                except Exception:
                    pass

            cache_hit = self._guess_cache_hit(lowered)

            http_version = getattr(resp, "http_version", None)
            ja3 = getattr(resp, "ja3", None)
            alpn = getattr(resp, "alpn", None)

            body_bytes = body_text.encode("utf-8", errors="ignore")
            body_len = len(body_bytes)
            body_md5 = hashlib.md5(body_bytes).hexdigest()
            body_ssdeep = ssdeep.hash(body_text) if _HAS_SSDEEP else None
            header_entropy = self._shannon_entropy(" ".join(f"{k}:{v}" for k, v in lowered.items()))
            cookie_fp = self._cookie_fingerprint(lowered)

            norm = NormalizedResponse(
                url=test_url,
                status_code=int(status),
                headers=lowered,
                text=body_text,
                http_version=http_version,
                ja3=ja3,
                alpn=alpn,
                hops=hops,
                cache_hit=cache_hit,
                timing_ms=elapsed_ms,
                persona_id=pid,
                cookie_fp=cookie_fp,
                body_len=body_len,
                body_md5=body_md5,
                body_ssdeep=body_ssdeep,
                header_entropy=header_entropy,
            )
            self._record_timing(url, pid, elapsed_ms)
            return norm

        except Exception as e:
            logger.debug(f"Request failed for {test_url} (persona={pid}): {e}")
            return None

    async def _run_passive_tests(self, baseline: Optional[NormalizedResponse]) -> Tuple[Dict[str, float], Dict[str, List[ProofArtifact]]]:
        results: Dict[str, float] = {}
        proofs: Dict[str, List[ProofArtifact]] = {}
        if not baseline:
            return results, proofs

        for waf_key, signature in self.signatures.items():
            total = 0.0
            for test in signature.tests:
                if test.type != "passive":
                    continue
                if self._evaluate_test(test, baseline):
                    score = test.score
                    score += self._boost_from_signals(baseline, baseline, passive=True)
                    total += min(score, 1.0)

                    pf = ProofArtifact(
                        baseline=baseline,
                        observed=baseline,
                        signals=self._signals_dict(baseline, baseline, label_edge=True),
                    )
                    proofs.setdefault[waf_key] if hasattr(proofs, 'setdefault') else None
                    proofs.setdefault(waf_key, []).append(pf)

            if total > 0:
                results[waf_key] = min(total, 1.0)
        return results, proofs

    async def _run_active_tests(self, target_url: str, http_client) -> Tuple[Dict[str, float], Dict[str, List[ProofArtifact]]]:
        results: Dict[str, float] = {}
        proofs: Dict[str, List[ProofArtifact]] = {}

        jobs: List[Tuple[str, WAFTest]] = []
        for waf_key, signature in self.signatures.items():
            for t in signature.tests:
                if t.type == "active":
                    jobs.append((waf_key, t))

        async def run_one(waf_key: str, test: WAFTest) -> Tuple[str, float, Optional[ProofArtifact]]:
            baseline = self.baselines.get(target_url)
            r1 = await self._make_request(target_url, http_client, payload=test.payload)
            replay_persona = self._different_persona(r1.persona_id if r1 else None)
            r2 = await self._make_request(target_url, http_client, payload=test.payload, persona_id=replay_persona)

            best_resp = r1 or r2
            if not best_resp:
                return waf_key, 0.0, None

            if self._evaluate_test(test, best_resp):
                score = test.score
                score += self._boost_from_signals(baseline, best_resp, passive=False)
                if r1 and r2 and self._responses_similar(r1, r2):
                    score += 0.1
                    
                edge = self._edge_mirror_hints(best_resp.headers)
                if edge:
                    score *= 0.8 

                score = max(0.0, min(score, 1.0))

                pf = ProofArtifact(
                    baseline=baseline,
                    observed=best_resp,
                    signals=self._signals_dict(baseline, best_resp, label_edge=True),
                )
                return waf_key, score, pf

            return waf_key, 0.0, None

        tasks = [asyncio.create_task(run_one(wk, t)) for wk, t in jobs]
        for res in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(res, Exception):
                logger.error(f"Active test task error: {res}")
                continue
            waf_key, conf, pf = res
            if conf > 0.0:
                results[waf_key] = max(results.get(waf_key, 0.0), conf)
                if pf:
                    proofs.setdefault(waf_key, []).append(pf)

        return results, proofs

    def _evaluate_test(self, test: WAFTest, resp: NormalizedResponse) -> bool:
        try:
            value: Optional[str] = None

            if test.path.startswith("header::"):
                header_name = test.path.split("::", 1)[1].lower()
                value = (resp.headers.get(header_name, "") or "").lower()

            elif test.path == "response::code":
                value = str(resp.status_code)

            elif test.path == "response::body":
                value = resp.text.lower()

            if value is None:
                return False

            patterns = test.pattern if isinstance(test.pattern, list) else [test.pattern]
            if test.match == "all":
                return all(re.search(p, value, re.IGNORECASE) is not None for p in patterns)
            return any(re.search(p, value, re.IGNORECASE) is not None for p in patterns)

        except Exception as e:
            logger.error(f"Error evaluating test {test.path}: {e}")
            return False

    def _boost_from_signals(self, baseline: Optional[NormalizedResponse], observed: NormalizedResponse, passive: bool) -> float:
        boost = 0.0
        if not baseline:
            return boost
        
        if baseline.status_code != observed.status_code:
            boost += 0.15
        len_ratio = abs(observed.body_len - max(1, baseline.body_len)) / max(1.0, baseline.body_len)
        if len_ratio >= 0.30:
            boost += 0.10

        if baseline.cookie_fp != observed.cookie_fp:
            boost += 0.15

        if abs(observed.header_entropy - baseline.header_entropy) >= 0.5:
            boost += 0.10

        if _HAS_SSDEEP and baseline.body_ssdeep and observed.body_ssdeep:
            try:
                sim = ssdeep.compare(baseline.body_ssdeep, observed.body_ssdeep) 
                if sim <= 40: 
                    boost += 0.10
            except Exception:
                pass

        pstats = self._persona_stats(observed.url, observed.persona_id)
        if pstats:
            median, p95, iqr = pstats
            if median and observed.timing_ms > median + max(10.0, iqr):
                boost += 0.05

        if passive:
            boost *= 0.7

        return max(0.0, min(boost, 0.5))

    def _responses_similar(self, r1: NormalizedResponse, r2: NormalizedResponse) -> bool:
        if r1.status_code != r2.status_code:
            return False
        if abs(r1.body_len - r2.body_len) > max(64, 0.1 * max(r1.body_len, r2.body_len)):
            return False
        if _HAS_SSDEEP and r1.body_ssdeep and r2.body_ssdeep:
            try:
                sim = ssdeep.compare(r1.body_ssdeep, r2.body_ssdeep)
                if sim < 60:
                    return False
            except Exception:
                pass
        return True

    def _signals_dict(self, baseline: Optional[NormalizedResponse], observed: NormalizedResponse, label_edge: bool) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "persona_id": observed.persona_id,
            "ja3": observed.ja3,
            "alpn": observed.alpn,
            "http_version": observed.http_version,
            "hops": observed.hops,
            "cache_hit": observed.cache_hit,
            "status": observed.status_code,
            "cookie_fp": observed.cookie_fp,
            "body_len": observed.body_len,
            "body_md5": observed.body_md5,
            "body_ssdeep": observed.body_ssdeep,
            "header_entropy": observed.header_entropy,
            "timing_ms": observed.timing_ms,
        }
        if baseline:
            d.update({
                "delta_status": observed.status_code - baseline.status_code,
                "delta_len": observed.body_len - baseline.body_len,
                "delta_entropy": observed.header_entropy - baseline.header_entropy,
                "cookie_fp_changed": observed.cookie_fp != baseline.cookie_fp,
            })
            if _HAS_SSDEEP and baseline.body_ssdeep and observed.body_ssdeep:
                try:
                    d["ssdeep_similarity"] = ssdeep.compare(baseline.body_ssdeep, observed.body_ssdeep)
                except Exception:
                    d["ssdeep_similarity"] = None
        if label_edge:
            d["edge_mirror"] = self._edge_mirror_hints(observed.headers)
        return d

    def _edge_mirror_hints(self, headers: Mapping[str, str]) -> bool:
        h = headers or {}
        keys = " ".join(h.keys())
        vals = " ".join(h.values())
        blob = f"{keys} {vals}".lower()

        hints = [
            "cf-ray", "cloudflare", "cf-cache-status", "cdn-cache", "akamai",
            "x-akamai", "x-cache", "x-served-by", "fastly", "x-fastly",
            "x-cdn", "x-cache-hits", "x-amz-cf-id", "akamai-",
        ]
        return any(token in blob for token in hints)

    def _edge_downrank_factor(self, proof_list: List[ProofArtifact]) -> float:
        try:
            for pf in proof_list:
                if pf.signals.get("edge_mirror"):
                    return 0.85
        except Exception:
            pass
        return 1.0

    def _guess_cache_hit(self, headers: Mapping[str, str]) -> Optional[bool]:
        xcache = headers.get("x-cache", "") or ""
        cfstatus = headers.get("cf-cache-status", "") or ""
        age = headers.get("age", "") or ""
        if "hit" in xcache.lower() or "hit" in cfstatus.lower():
            return True
        if age.isdigit() and int(age) > 0:
            return True
        if "miss" in xcache.lower() or "miss" in cfstatus.lower():
            return False
        return None

    def _cookie_fingerprint(self, headers: Mapping[str, str]) -> str:
        sc = headers.get("set-cookie", "")
        if not sc:
            return "none"
        parts = [p.strip() for p in re.split(r",(?=[^ ;]+=)", sc)]
        names = []
        for p in parts:
            name = p.split("=", 1)[0].strip().lower()
            attrs = set()
            for attr in ["httponly", "secure", "samesite", "path", "domain", "max-age"]:
                if re.search(rf"\b{attr}\b", p, re.I):
                    attrs.add(attr)
            names.append(f"{name};{'|'.join(sorted(attrs))}")
        names.sort()
        digest = hashlib.sha1((";".join(names)).encode("utf-8")).hexdigest()
        return digest

    def _shannon_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        freq = {}
        for ch in s:
            freq[ch] = freq.get(ch, 0) + 1
        total = float(len(s))
        ent = 0.0
        for c in freq.values():
            p = c / total
            ent -= p * math.log2(p)
        return ent

    def _record_timing(self, target_url: str, persona_id: str, ms: float) -> None:
        key = (target_url, persona_id or "unknown")
        arr = self.timings.setdefault(key, [])
        arr.append(ms)
        if len(arr) > 50:
            del arr[:-50]

    def _persona_stats(self, target_url: str, persona_id: str) -> Optional[Tuple[float, float, float]]:
        arr = self.timings.get((target_url, persona_id or "unknown"))
        if not arr:
            return None
        med = statistics.median(arr)
        p95 = statistics.quantiles(arr, n=100)[94] if len(arr) >= 20 else max(arr)
        iqr = 0.0
        if len(arr) >= 8:
            q1, q3 = statistics.quantiles(arr, n=4)[0], statistics.quantiles(arr, n=4)[2]
            iqr = max(0.0, q3 - q1)
        return med, p95, iqr

    def _different_persona(self, current: Optional[str]) -> str:
        ids = [p for p, _ in self.user_agents]
        if not current or current not in ids:
            return random.choice(ids)
        others = [p for p in ids if p != current]
        return random.choice(others) if others else current

    def _merge_proofs(self, dst: Dict[str, List[ProofArtifact]], src: Dict[str, List[ProofArtifact]]) -> None:
        for k, v in src.items():
            dst.setdefault(k, []).extend(v)
