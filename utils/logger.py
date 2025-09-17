from __future__ import annotations
import json
import logging
import logging.handlers
import os
import re
import sys
import time
import inspect
import threading
from datetime import datetime
from typing import Any, Dict, Optional

try:
    from threat_intelligence import ThreatIntelClient  
except Exception: 
    ThreatIntelClient = None

class ForensicHandler(logging.Handler):
    def __init__(self, evidence_dir: str = "forensic_evidence"):
        super().__init__()
        self.evidence_dir = evidence_dir
        os.makedirs(self.evidence_dir, exist_ok=True)
        self._lock = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        if not hasattr(record, "forensic_data"):
            return
        try:
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
            mod = getattr(record, "module", "unknown")
            func = getattr(record, "funcName", "unknown")
            fname = f"{ts}_{mod}_{func}.json"
            path = os.path.join(self.evidence_dir, fname)

            payload = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "level": record.levelname,
                "logger": record.name,
                "module": mod,
                "function": func,
                "line": getattr(record, "lineno", 0),
                "message": record.getMessage(),
                "data": getattr(record, "forensic_data", {}),
            }
            with self._lock, open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
        except Exception:
            self.handleError(record)

class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = {
            "timestamp": datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "message": record.getMessage(),
        }
        if hasattr(record, "threat_intel"):
            base["threat_intel"] = getattr(record, "threat_intel")
        if hasattr(record, "forensic_data"):
            base["forensic_data"] = getattr(record, "forensic_data")
        return json.dumps(base, ensure_ascii=False)

class ThreatIntelFormatter(logging.Formatter):
    def __init__(self, fmt: Optional[str] = None, datefmt: Optional[str] = None, style: str = "%", intel_client=None):
        super().__init__(fmt=fmt, datefmt=datefmt, style=style)
        self.intel_client = intel_client or (ThreatIntelClient() if ThreatIntelClient else None)

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        if record.levelno >= logging.WARNING and self.intel_client:
            try:
                iocs = self._extract_iocs(record.getMessage())
                if iocs:
                    intel = self.intel_client.lookup(iocs)  
                    setattr(record, "threat_intel", intel)
                    message += f" | ThreatIntel: {json.dumps(intel)}"
            except Exception:
                pass
        return message

    def _extract_iocs(self, message: str) -> list:
        iocs: list[str] = []
        ip_pat = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        iocs.extend(re.findall(ip_pat, message))
        dom_pat = r"\b(?:[a-z0-9]+(?:-[a-z0-9]+)*\.)+[a-z]{2,}\b"
        iocs.extend(re.findall(dom_pat, message, flags=re.IGNORECASE))
        hash_pat = r"\b[a-f0-9]{32,128}\b"
        iocs.extend(re.findall(hash_pat, message, flags=re.IGNORECASE))
        return sorted(set(iocs))


class PerformanceFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.name.endswith(".performance")


class NotPerformanceFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return not record.name.endswith(".performance")


class Logger:
    _instance: Optional["Logger"] = None

    def __new__(cls, *args, **kwargs) -> "Logger":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance 

    def __init__(
        self,
        name: str = "Nuke403",
        log_level: str = "INFO",
        log_file: Optional[str] = None,
        syslog_server: Optional[str] = None,
        enable_forensics: bool = True,
        enable_perf_mon: bool = True,
        json_console: bool = False,
        json_file: bool = False,
        config: Optional[Dict[str, Any]] = None,
    ):
        if getattr(self, "_initialized", False):
            return
        self._initialized = True
        self.config = config or {}
        self.name = name
        self.log_level = getattr(logging, log_level.upper(), logging.INFO)
        self.enable_forensics = enable_forensics
        self.enable_perf_mon = enable_perf_mon
        self.json_console = bool(json_console or self.config.get("json_console"))
        self.json_file = bool(json_file or self.config.get("json_file"))
        self.logger = logging.getLogger(name)
        self.logger.setLevel(self.log_level)
        self.logger.propagate = False
        self.perf_logger = logging.getLogger(f"{name}.performance")
        self.perf_logger.setLevel(logging.DEBUG)
        self.perf_logger.propagate = False
        self._setup_handlers(log_file=log_file or self.config.get("log_file"),
                             syslog_server=syslog_server or self.config.get("syslog_server"))
        self._tl = threading.local()

    def _setup_handlers(self, *, log_file: Optional[str], syslog_server: Optional[str]) -> None:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.addFilter(NotPerformanceFilter())
        if self.json_console:
            console_handler.setFormatter(JSONFormatter())
        else:
            console_fmt = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
            console_handler.setFormatter(ThreatIntelFormatter(console_fmt))
        self.logger.addHandler(console_handler)

        if log_file:
            file_handler = logging.handlers.RotatingFileHandler(
                log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
            )
            if self.json_file:
                file_handler.setFormatter(JSONFormatter())
            else:
                file_fmt = "%(asctime)s | %(levelname)s | %(name)s | %(module)s:%(lineno)d | %(message)s"
                file_handler.setFormatter(logging.Formatter(file_fmt))
            self.logger.addHandler(file_handler)

        if syslog_server:
            try:
                if ":" in syslog_server:
                    host, port = syslog_server.split(":", 1)
                    address = (host, int(port))
                else:
                    address = (syslog_server, 514)
                syslog_handler = logging.handlers.SysLogHandler(
                    address=address, facility=logging.handlers.SysLogHandler.LOG_LOCAL0
                )
                syslog_fmt = "%(name)s %(levelname)s %(module)s:%(lineno)d %(message)s"
                syslog_handler.setFormatter(logging.Formatter(syslog_fmt))
                self.logger.addHandler(syslog_handler)
            except Exception as e:
                self.logger.error(f"Failed to setup syslog: {e}")

        if self.enable_forensics:
            forensic_dir = self.config.get("forensic_dir", "forensic_evidence")
            self.logger.addHandler(ForensicHandler(forensic_dir))

        if self.enable_perf_mon:
            perf_handler = logging.StreamHandler(sys.stdout)
            perf_handler.setFormatter(logging.Formatter("%(asctime)s | PERF | %(name)s | %(message)s"))
            perf_handler.addFilter(PerformanceFilter())
            self.perf_logger.addHandler(perf_handler)

    def set_level(self, level: str) -> None:
        new_level = getattr(logging, level.upper(), None)
        if new_level is not None:
            self.log_level = new_level
            self.logger.setLevel(new_level)

    def debug(self, msg: str, forensic_data: Optional[Dict[str, Any]] = None, **kwargs: Any) -> None:
        self._log(logging.DEBUG, msg, forensic_data, **kwargs)

    def info(self, msg: str, forensic_data: Optional[Dict[str, Any]] = None, **kwargs: Any) -> None:
        self._log(logging.INFO, msg, forensic_data, **kwargs)

    def warning(self, msg: str, forensic_data: Optional[Dict[str, Any]] = None, **kwargs: Any) -> None:
        self._log(logging.WARNING, msg, forensic_data, **kwargs)

    def error(self, msg: str, forensic_data: Optional[Dict[str, Any]] = None, **kwargs: Any) -> None:
        self._log(logging.ERROR, msg, forensic_data, **kwargs)

    def critical(self, msg: str, forensic_data: Optional[Dict[str, Any]] = None, **kwargs: Any) -> None:
        self._log(logging.CRITICAL, msg, forensic_data, **kwargs)

    def _log(self, level: int, msg: str, forensic_data: Optional[Dict[str, Any]], **kwargs: Any) -> None:
        frame = inspect.currentframe()
        caller = frame.f_back.f_back if frame and frame.f_back and frame.f_back.f_back else None  
        module = inspect.getmodule(caller).__name__ if caller else self.name
        func_name = caller.f_code.co_name if caller else "unknown"
        lineno = caller.f_lineno if caller else 0

        extra = {"module": module, "funcName": func_name, "lineno": lineno}
        if forensic_data:
            extra["forensic_data"] = forensic_data
        self.logger.log(level, msg, extra=extra, **kwargs)

    def start_timer(self, name: str) -> None:
        if not hasattr(self._tl, "timers"):
            self._tl.timers = {}
        self._tl.timers[name] = time.perf_counter()

    def end_timer(self, name: str, message: str = "") -> Optional[float]:
        timers = getattr(self._tl, "timers", {})
        if name not in timers:
            return None
        start = timers.pop(name)
        dur = time.perf_counter() - start
        self.perf_logger.info(f"{message} | {name}={self._humanize_duration(dur)} ({dur:.6f}s)")
        return dur

    @staticmethod
    def _humanize_duration(seconds: float) -> str:
        if seconds < 1e-6:
            return f"{seconds * 1e9:.2f}ns"
        if seconds < 1e-3:
            return f"{seconds * 1e6:.2f}μs"
        if seconds < 1:
            return f"{seconds * 1e3:.2f}ms"
        return f"{seconds:.2f}s"

    def log_http_request(self, method: str, url: str, status: int, duration: float, size_bytes: int) -> None:
        self.info(f"HTTP | {method} {url} | {status} | {self._humanize_duration(duration)} | {size_bytes} bytes")

    def log_security_event(self, event_type: str, target: str, details: Dict[str, Any]) -> None:
        forensic_data = {"event_type": event_type, "target": target, "details": details}
        self.warning(f"SECURITY | {event_type} | {target}", forensic_data=forensic_data)

    def log_bypass(self, technique: str, target: str, payload: str, status: int) -> None:
        forensic_data = {"technique": technique, "target": target, "payload": payload, "status": status}
        self.info(f"BYPASS | {technique} | {target} | {payload} → {status}", forensic_data=forensic_data)

    def log_ai_event(self, model: str, action: str, input_data: Dict[str, Any], output_data: Dict[str, Any]) -> None:
        forensic_data = {"model": model, "action": action, "input": input_data, "output": output_data}
        self.debug(f"AI | {model} | {action}", forensic_data=forensic_data)
        
logger = Logger()
