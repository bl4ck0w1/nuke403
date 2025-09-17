from __future__ import annotations
import asyncio
import logging
import random
import string
import hashlib
from dataclasses import dataclass
from typing import Dict, Optional, Any, Tuple

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
except Exception:  
    TfidfVectorizer = None
    cosine_similarity = None

try:
    import ssdeep
except Exception:  
    ssdeep = None

try:
    import tlsh  
except Exception: 
    tlsh = None

try:
    from datasketch import MinHash
except Exception: 
    MinHash = None

logger = logging.getLogger(__name__)

@dataclass
class SimpleFingerprint:
    status: int
    length: int
    cookie_fp: str
    headers_fp: str
    header_entropy: float
    ssdeep_hash: Optional[str]
    tlsh_hash: Optional[str]

    @staticmethod
    def header_entropy(headers: Dict[str, str]) -> float:
        if not headers:
            return 0.0
        from math import log2
        s = ";".join(f"{k.lower()}={str(v)[:128]}" for k, v in headers.items())
        freq: Dict[str, int] = {}
        for ch in s:
            freq[ch] = freq.get(ch, 0) + 1
        n = len(s)
        return -sum((c / n) * log2(c / n) for c in freq.values())

    @classmethod
    def from_http(cls, response: Any) -> "SimpleFingerprint":
        status = int(getattr(response, "status_code", 0) or 0)
        text = (getattr(response, "text", "") or "")
        headers: Dict[str, str] = (getattr(response, "headers", {}) or {})
        set_cookie = headers.get("Set-Cookie") or headers.get("set-cookie") or ""

        cookie_fp = hashlib.md5(set_cookie.encode("utf-8", errors="ignore")).hexdigest()
        header_str = ";".join(f"{k.lower()}={str(v)[:128]}" for k, v in headers.items())
        headers_fp = hashlib.md5(header_str.encode("utf-8", errors="ignore")).hexdigest()
        ent = cls.header_entropy(headers)

        ssd = ssdeep.hash(text) if (ssdeep and text) else None
        tlh = None
        if tlsh and text:
            try:
                tlh = tlsh.hash(text.encode("utf-8", errors="ignore"))
            except Exception:
                tlh = None

        return cls(
            status=status,
            length=len(text),
            cookie_fp=cookie_fp,
            headers_fp=headers_fp,
            header_entropy=ent,
            ssdeep_hash=ssd,
            tlsh_hash=tlh,
        )


def _minhash_similarity(a: str, b: str) -> Optional[float]:
    if not MinHash:
        return None
    try:
        def shingles(s: str, k: int = 5):
            s = s or ""
            return {s[i:i+k] for i in range(max(0, len(s) - k + 1))}
        mh1, mh2 = MinHash(num_perm=64), MinHash(num_perm=64)
        for sh in shingles(a):
            mh1.update(sh.encode("utf-8", errors="ignore"))
        for sh in shingles(b):
            mh2.update(sh.encode("utf-8", errors="ignore"))
        return mh1.jaccard(mh2)
    except Exception:
        return None

class TripleValidator:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(stop_words="english", max_features=2000) if TfidfVectorizer else None
        self.baseline_map: Dict[str, Dict[str, Any]] = {} 

    async def validate(self, bypass_result: Dict, http_client) -> bool:
        url = bypass_result.get("url", "")
        if not url:
            logger.debug("Validation skipped: missing URL")
            return False

        candidate = await self._ensure_candidate_payload(bypass_result, http_client)
        if not candidate:
            return False

        if not self._behavioral_validation(candidate):
            return False

        if not await self._content_validation(url, candidate):
            return False

        if not await self._shadow_validation(url, candidate, http_client):
            return False

        return True

    def set_baseline_response(self, url: str, response: Dict) -> None:
        try:
            fake_resp = _DictAsResp(response)
            self.baseline_map[url] = {
                "text": response.get("text", "") or response.get("body", "") or "",
                "headers": response.get("headers", {}) or {},
                "status": int(response.get("status_code", 0) or 0),
                "fp": SimpleFingerprint.from_http(fake_resp),
            }
        except Exception as e:
            logger.debug(f"Failed to store baseline for {url}: {e}")

    def _behavioral_validation(self, candidate: Dict) -> bool:
        status = int(candidate.get("status_code", 0) or 0)
        size = int(candidate.get("response_size", 0) or 0)

        if not (200 <= status < 300):
            logger.debug(f"Behavioral validation: non-2xx status ({status})")
            return False

        if size < 32:
            logger.debug(f"Behavioral validation: body too small ({size} bytes)")
            return False

        body_lc = (candidate.get("response_text", "") or "").lower()
        block_terms = [
            "access denied", "forbidden", "unauthorized", "not authorized",
            "blocked", "captcha", "bot verification", "attention required",
            "request blocked", "waf"
        ]
        if any(t in body_lc for t in block_terms):
            logger.debug("Behavioral validation: body contains block-page indicators")
            return False

        return True

    async def _content_validation(self, url: str, candidate: Dict) -> bool:
        base = self.baseline_map.get(url)
        if not base:
            return not self._is_likely_waf_mirror(candidate)

        base_text = base.get("text", "") or ""
        cand_text = candidate.get("response_text", "") or ""
        base_fp: SimpleFingerprint = base.get("fp") 
        cand_fp = self._fingerprint_from_dict(candidate)
        tfidf_sim = self._tfidf_similarity(base_text, cand_text)
        mh_sim = _minhash_similarity(base_text, cand_text)
        ssd_sim = self._ssdeep_similarity(base_text, cand_text)
        tlsh_dist = self._tlsh_distance(base_text, cand_text)
        cookie_changed = cand_fp.cookie_fp != base_fp.cookie_fp
        headers_changed = cand_fp.headers_fp != base_fp.headers_fp
        entropy_delta = abs(cand_fp.header_entropy - base_fp.header_entropy)
        length_diff_ratio = abs(cand_fp.length - base_fp.length) / max(1, max(cand_fp.length, base_fp.length))
        status_improved = (base_fp.status in (401, 403)) and (200 <= cand_fp.status < 300)

        signals = 0

        if tfidf_sim is not None and tfidf_sim < 0.75: 
            signals += 1
        if mh_sim is not None and mh_sim < 0.75:
            signals += 1
        if ssd_sim is not None and ssd_sim < 0.75:
            signals += 1
        if tlsh_dist is not None and tlsh_dist > 20: 
            signals += 1

        if cookie_changed:
            signals += 1
        if headers_changed or entropy_delta > 0.5:
            signals += 1
        if length_diff_ratio > 0.15:
            signals += 1
        if status_improved:
            signals += 1

        if self._looks_like_same_cluster(base, candidate):
            logger.debug("Content validation: likely same WAF/CDN mirror cluster")
            return False

        if signals >= 2:
            return True

        logger.debug(f"Content validation: insufficient difference signals ({signals})")
        return False

    def _tfidf_similarity(self, a: str, b: str) -> Optional[float]:
        if not a or not b:
            return None
        if self.vectorizer and cosine_similarity:
            try:
                tfidf = self.vectorizer.fit_transform([a, b])
                return float(cosine_similarity(tfidf[0:1], tfidf[1:2])[0][0])
            except Exception:
                pass
            
        def trigrams(s: str):
            s = s or ""
            return {s[i:i+3] for i in range(max(0, len(s) - 2))}
        s1, s2 = trigrams(a), trigrams(b)
        if not s1 and not s2:
            return None
        inter = len(s1 & s2)
        union = len(s1 | s2) or 1
        return inter / union

    def _ssdeep_similarity(self, a: str, b: str) -> Optional[float]:
        if not ssdeep or not a or not b:
            return None
        try:
            h1, h2 = ssdeep.hash(a), ssdeep.hash(b)
            if not h1 or not h2:
                return None
            return ssdeep.compare(h1, h2) / 100.0  
        except Exception:
            return None

    def _tlsh_distance(self, a: str, b: str) -> Optional[int]:
        if not tlsh or not a or not b:
            return None
        try:
            h1 = tlsh.hash(a.encode("utf-8", errors="ignore"))
            h2 = tlsh.hash(b.encode("utf-8", errors="ignore"))
            if not h1 or not h2:
                return None
            return tlsh.diff(h1, h2)  
        except Exception:
            return None

    def _looks_like_same_cluster(self, base: Dict, cand: Dict) -> bool:
        def fold(d: Dict[str, str]) -> Dict[str, str]:
            return {str(k).lower(): str(v).lower() for k, v in (d or {}).items()}

        bh = fold(base.get("headers", {}))
        ch = fold(cand.get("headers", {}))

        waf_markers = [
            "cf-ray", "cf-cache-status", "server: cloudflare", "x-akamai-",
            "akamai-", "x-iinfo", "incap-ses", "x-cdn", "bigipserver", "f5-"
        ]
        joined_b = ";".join(f"{k}:{v}" for k, v in bh.items())
        joined_c = ";".join(f"{k}:{v}" for k, v in ch.items())

        same_vendor_hints = sum(1 for m in waf_markers if m in joined_b) >= 1 and \
                            sum(1 for m in waf_markers if m in joined_c) >= 1

        identical_cf_ray = bh.get("cf-ray") and bh.get("cf-ray") == ch.get("cf-ray")

        return bool(same_vendor_hints and (identical_cf_ray or bh == ch))

    def _is_likely_waf_mirror(self, candidate: Dict) -> bool:
        headers = {str(k).lower(): str(v).lower() for k, v in (candidate.get("headers", {}) or {}).items()}
        body = (candidate.get("response_text", "") or "").lower()
        markers = [
            "cloudflare", "akamai", "imperva", "bigip", "fortiweb", "aws waf",
            "attention required", "request blocked", "captcha"
        ]
        return any(m in body for m in markers) or any("cf-ray" in k or "akamai" in k for k in headers.keys())

    def _fingerprint_from_dict(self, d: Dict) -> SimpleFingerprint:
        fake_resp = _DictAsResp({
            "status_code": d.get("status_code", 0),
            "text": d.get("response_text", "") or "",
            "headers": d.get("headers", {}) or {},
        })
        return SimpleFingerprint.from_http(fake_resp)


    async def _shadow_validation(self, url: str, candidate: Dict, http_client) -> bool:
        try:
            base = url.rstrip("/")
            rand1 = self._random_token()
            rand2 = self._random_token()
            decoys = [f"{base}/{rand1}", f"{base.rsplit('/', 1)[0]}/{rand2}" if "/" in base[8:] else f"{base}/{rand2}"]

            cand_size = int(candidate.get("response_size", 0) or 0)

            for durl in decoys:
                r = await http_client.get(durl, timeout=8)
                if 200 <= int(getattr(r, "status_code", 0)) < 300:
                    text = getattr(r, "text", "") or ""
                    ratio = self._size_similarity_ratio(cand_size, len(text))
                    if ratio > 0.80:
                        logger.debug(f"Shadow validation: decoy also 2xx and similar size ({ratio:.2f})")
                        return False
            return True
        except Exception as e:
            logger.debug(f"Shadow validation error: {e}")
            return True

    async def _ensure_candidate_payload(self, bypass_result: Dict, http_client) -> Optional[Dict]:
        url = bypass_result.get("url")
        if not url:
            return None

        text = bypass_result.get("response_text")
        headers = bypass_result.get("headers")
        status = bypass_result.get("status_code")
        size = bypass_result.get("response_size")

        if text is not None and headers is not None and status is not None and size is not None:
            return {
                "url": url,
                "status_code": int(status),
                "headers": headers,
                "response_text": text,
                "response_size": int(size),
            }

        try:
            r = await http_client.get(url, timeout=12)
            t = getattr(r, "text", "") or ""
            h = getattr(r, "headers", {}) or {}
            s = int(getattr(r, "status_code", 0) or 0)
            return {
                "url": url,
                "status_code": s,
                "headers": h,
                "response_text": t,
                "response_size": len(t),
            }
        except Exception as e:
            logger.debug(f"Refetch candidate failed: {e}")
            return None

    @staticmethod
    def _random_token(n: int = 10) -> str:
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

    @staticmethod
    def _size_similarity_ratio(a: int, b: int) -> float:
        a, b = int(a or 0), int(b or 0)
        if a == 0 and b == 0:
            return 1.0
        if max(a, b) == 0:
            return 0.0
        return min(a, b) / max(a, b)

class _DictAsResp:
    def __init__(self, d: Dict[str, Any]):
        self.status_code = d.get("status_code", 0)
        self.text = d.get("text", d.get("body", "")) or ""
        self.headers = d.get("headers", {}) or {}
