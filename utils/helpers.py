from __future__ import annotations
import re
import hashlib
import ipaddress
import random
import string
import binascii
import threading
from collections import OrderedDict
from typing import Dict, List, Tuple, Set, Optional
from urllib.parse import urlparse, quote, unquote
from difflib import SequenceMatcher


class NSAHelpers:
    def __init__(self, max_cache_size: int = 5000):
        self.cache: OrderedDict[str, object] = OrderedDict()
        self._lock = threading.Lock()
        self.max_cache_size = max_cache_size
        self.request_counter = 0
        self.cache_hits = 0
        self._block_patterns = [
            re.compile(r"<title>.*(Access\s+Denied|Forbidden|Blocked).*</title>", re.I | re.S),
            re.compile(r"<h\d[^>]*>.*(Security\s+Violation|Unauthorized).*</h\d>", re.I | re.S),
            re.compile(r'class\s*=\s*["\']?[^"\']*block-page[^"\']*["\']?', re.I),
            re.compile(r'id\s*=\s*["\']?blockPage["\']?', re.I),
            re.compile(r'cf[- ]?ray', re.I), 
        ]

    def _cache_get(self, key: str):
        with self._lock:
            val = self.cache.get(key)
            if val is not None:
                self.cache.move_to_end(key) 
                self.cache_hits += 1
            return val

    def _cache_set(self, key: str, value: object):
        with self._lock:
            self.cache[key] = value
            self.cache.move_to_end(key)
            if len(self.cache) > self.max_cache_size:
                self.cache.popitem(last=False)  

    def dotless_ip_encode(self, ip_address: str) -> str:
        cache_key = f"ip_encode_{ip_address}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached  

        self.request_counter += 1
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.version == 4:
                hex_ip = hex(int(ip_obj))[2:].zfill(8)
                result = f"0x{hex_ip}"
            elif ip_obj.version == 6:
                result = f"0x{ip_obj.packed.hex()}"  
            else:
                result = ip_address
        except ValueError:
            result = ip_address

        self._cache_set(cache_key, result)
        return result

    def dotless_ip_decode(self, hex_str: str) -> str:
        cache_key = f"ip_decode_{hex_str}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached 

        self.request_counter += 1
        out = hex_str
        try:
            if hex_str.startswith("0x"):
                body = hex_str[2:]
                if len(body) == 8: 
                    out = ".".join(str(int(body[i : i + 2], 16)) for i in range(0, 8, 2))
                elif len(body) == 32:  
                    out = str(ipaddress.IPv6Address(bytes.fromhex(body)))
        except Exception:
            pass

        self._cache_set(cache_key, out)
        return out

    def normalize_path(self, path: str, preserve_trailing_slash: bool = False) -> str:
        cache_key = f"normalize_{path}|{int(preserve_trailing_slash)}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached 

        self.request_counter += 1
        decoded = unquote(path or "/")
        had_trailing = decoded.endswith("/")
        normalized = re.sub(r"/{2,}", "/", decoded)
        segments: List[str] = []
        for seg in normalized.split("/"):
            if seg == "..":
                if segments:
                    segments.pop()
            elif seg in ("", "."):
                continue
            else:
                segments.append(seg)

        result = "/" + "/".join(segments)
        if preserve_trailing_slash and had_trailing and result != "/":
            result += "/"

        self._cache_set(cache_key, result)
        return result

    def generate_bypass_payloads(self, base_path: str, techniques: List[str]) -> List[str]:
        cache_key = f"bypass_{base_path}_{'_'.join(sorted(techniques))}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        self.request_counter += 1
        payloads: Set[str] = set()

        if "trim_chars" in techniques:
            trim_chars = ["%09", "%0A", "%0D", "%0C", "%A0", "%85", "%1F", "%1E", "%1D", "%1C"]
            for char in trim_chars:
                payloads.add(f"{base_path}{char}")
                payloads.add(f"{char}{base_path}")
                payloads.add(f"{base_path}/{char}test")

        if "double_slash" in techniques:
            payloads.add(f"//{base_path.lstrip('/')}")
            payloads.add(f"/{base_path.lstrip('/')}//")

        if "dot_smuggling" in techniques:
            payloads.add(f"/.%2e/{base_path.lstrip('/')}")
            payloads.add(f"/{base_path.lstrip('/')}/.%2e")
            payloads.add(f"/%2e%2e/{base_path.lstrip('/')}")

        if "matrix_parameters" in techniques:
            payloads.add(f"/;bypass/{base_path.lstrip('/')}")
            payloads.add(f"/{base_path.lstrip('/')};bypass=true")

        if "null_byte" in techniques:
            payloads.add(f"{base_path}%00")
            payloads.add(f"{base_path}%00.html")

        if "case_mangling" in techniques:
            payloads.add(base_path.upper())
            payloads.add(base_path.lower())
            payloads.add(base_path.swapcase())
            payloads.add(base_path[: len(base_path) // 2].upper() + base_path[len(base_path) // 2 :].lower())

        if "unicode_separators" in techniques:
            unicode_chars = ["%e2%81%af", "%e2%80%ab", "%e2%80%ac"]
            for char in unicode_chars:
                payloads.add(f"{base_path}{char}")
                payloads.add(f"{char}{base_path}")

        result = list(payloads)
        self._cache_set(cache_key, result)
        return result

    def calculate_content_similarity(self, content1: str, content2: str) -> float:
        cache_key = f"similarity_{hash(content1)}_{hash(content2)}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached 

        self.request_counter += 1

        seq_ratio = SequenceMatcher(None, content1, content2).ratio()

        tokens1 = {t for t in re.split(r"\W+", content1.lower()) if t}
        tokens2 = {t for t in re.split(r"\W+", content2.lower()) if t}
        if tokens1 and tokens2:
            jaccard = len(tokens1 & tokens2) / len(tokens1 | tokens2)
        else:
            jaccard = 0.0

        lines1 = content1.splitlines()
        lines2 = content2.splitlines()
        line_ratio = SequenceMatcher(None, lines1, lines2).ratio()

        result = (seq_ratio * 0.4) + (jaccard * 0.3) + (line_ratio * 0.3)
        self._cache_set(cache_key, result)
        return result

    def detect_block_page(self, content: str) -> bool:
        cache_key = f"blockpage_{hash(content)}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached 

        self.request_counter += 1
        c = content.lower()

        keywords = [
            "access denied",
            "forbidden",
            "blocked",
            "security violation",
            "not authorized",
            "unauthorized",
            "cloudflare",
            "incapsula",
            "akamai",
            "waf",
            "security policy",
            "request rejected",
            "captcha",
        ]
        if any(k in c for k in keywords):
            self._cache_set(cache_key, True)
            return True
        
        if c.count("<form") > 1 and "captcha" in c:
            self._cache_set(cache_key, True)
            return True

        for pat in self._block_patterns:
            if pat.search(content):
                self._cache_set(cache_key, True)
                return True

        self._cache_set(cache_key, False)
        return False

    def parse_headers(self, raw_headers: str) -> Dict[str, str]:
        cache_key = f"headers_{hash(raw_headers)}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        self.request_counter += 1
        headers: Dict[str, str] = {}
        current_header: Optional[str] = None

        for line in raw_headers.splitlines():
            if not line.strip():
                continue

            if line.startswith((" ", "\t")) and current_header:
                headers[current_header] = headers[current_header] + " " + line.strip()
                continue

            if ":" in line:
                name, value = line.split(":", 1)
                name = name.strip().title()
                value = value.strip()
                if name in headers:
                    headers[name] = f"{headers[name]}, {value}"
                else:
                    headers[name] = value
                current_header = name
            else:
                headers["X-Malformed-Header"] = line.strip()
                current_header = "X-Malformed-Header"

        self._cache_set(cache_key, headers)
        return headers

    def generate_malformed_header(self, name: str, value: str) -> List[Tuple[str, str]]:
        cache_key = f"malformed_{name}_{value}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached  

        self.request_counter += 1
        variants: List[Tuple[str, str]] = [
            (f"{name} ", value), 
            (f"{name}\tExtra", value),
            (name, f"{value}\nInjected"),
            (f"{name}:Extra", value),
            (f"{name}-✓", value),
            (name, "first\r\n second"),
            ("", value),  
        ]

        self._cache_set(cache_key, variants)
        return variants

    def extract_url_features(self, url: str) -> dict:
        cache_key = f"urlfeatures_{url}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached 

        self.request_counter += 1
        parsed = urlparse(url)
        path = parsed.path or "/"

        path_depth = max(0, len([s for s in path.split("/") if s]) - 0)

        features = {
            "scheme": parsed.scheme,
            "netloc": parsed.netloc,
            "path_depth": path_depth,
            "param_count": len(parsed.query.split("&")) if parsed.query else 0,
            "has_encoding": ("%" in (parsed.path or "")) or ("%" in (parsed.query or "")),
            "path_components": [],
            "param_patterns": [],
        }

        for segment in [s for s in path.split("/") if s]:
            features["path_components"].append(
                {
                    "length": len(segment),
                    "has_extension": "." in segment,
                    "is_numeric": segment.isdigit(),
                    "has_special": bool(re.search(r"[^a-zA-Z0-9\-_.~]", segment)),
                }
            )

        if parsed.query:
            for param in parsed.query.split("&"):
                if "=" in param:
                    key, value = param.split("=", 1)
                    features["param_patterns"].append(
                        {
                            "key_length": len(key),
                            "value_length": len(value),
                            "is_numeric_value": value.isdigit(),
                        }
                    )

        self._cache_set(cache_key, features)
        return features

    def generate_random_user_agent(self) -> str:
        cache_key = "random_ua_pool"
        pool = self._cache_get(cache_key)
        if pool is not None:
            return random.choice(pool) 

        self.request_counter += 1

        templates = {
            "Chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v} Safari/537.36",
            "Firefox": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{v}) "
                       "Gecko/20100101 Firefox/{v}",
            "Safari": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                      "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{v} Safari/605.1.15",
            "Edge": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 "
                    "Safari/537.36 Edg/{v}",
        }
        versions = {
            "Chrome": ["90.0.4430.212", "91.0.4472.124", "92.0.4515.107", "93.0.4577.63"],
            "Firefox": ["89.0", "90.0", "91.0", "92.0"],
            "Safari": ["14.1.2", "15.0", "15.1", "15.2"],
            "Edge": ["114.0.1823.58", "115.0.1901.183", "116.0.1938.81"],
        }

        ua_pool: List[str] = []
        for browser, tmpl in templates.items():
            for v in versions[browser]:
                ua_pool.append(tmpl.format(v=v))

        self._cache_set(cache_key, ua_pool)
        return random.choice(ua_pool)

    def calculate_confidence_score(self, indicators: List[Dict]) -> float:
        cache_key = f"confidence_{hash(str(indicators))}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached 

        self.request_counter += 1
        if not indicators:
            self._cache_set(cache_key, 0.0)
            return 0.0

        type_weights = {
            "signature_match": 0.95,
            "behavioral_match": 0.85,
            "structural_match": 0.75,
            "content_fingerprint": 0.99,
            "protocol_anomaly": 0.90,
        }

        weighted_sum = 0.0
        total_weight = 0.0
        for ind in indicators:
            weight = type_weights.get(ind.get("type", ""), 0.7)
            confidence = float(ind.get("confidence", 0.0))
            weighted_sum += weight * confidence
            total_weight += weight

        base = (weighted_sum / total_weight) if total_weight else 0.0
        count_boost = min(0.2, len(indicators) * 0.05)
        result = min(1.0, base + count_boost)

        self._cache_set(cache_key, result)
        return result

    def get_cache_stats(self) -> Dict[str, float]:
        with self._lock:
            requests = self.request_counter or 1
            return {
                "cache_size": float(len(self.cache)),
                "requests": float(self.request_counter),
                "cache_hits": float(self.cache_hits),
                "hit_ratio": float(self.cache_hits) / requests,
            }

    def clear_cache(self):
        with self._lock:
            self.cache.clear()
            self.request_counter = 0
            self.cache_hits = 0

nsa_helpers = NSAHelpers()
