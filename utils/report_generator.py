import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import os
import shutil
import textwrap

try:
    from colorama import Fore as _Fore, Style as _Style, init as _colorama_init
    _colorama_init(autoreset=True)
    _COLORAMA_OK = True
except Exception: 
    class _Dummy:
        def __getattr__(self, _: str) -> str:
            return ""
    _Fore, _Style, _COLORAMA_OK = _Dummy(), _Dummy(), False

logger = logging.getLogger(__name__)


class ReportGenerator:
    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}
        no_color_env = os.environ.get("NO_COLOR") is not None
        self.color_enabled = bool(self.config.get("color_output", True)) and _COLORAMA_OK and not no_color_env
        self.verbose = bool(self.config.get("verbose", False))
        self.wrap = int(self.config.get("wrap", 0)) 
        self.sort_success = bool(self.config.get("sort_success", True))

    def _term_width(self) -> int:
        if self.wrap > 0:
            return max(40, self.wrap)
        try:
            cols = shutil.get_terminal_size(fallback=(100, 20)).columns
            return max(60, min(160, cols)) 
        except Exception:
            return 100

    def _c(self, color: str) -> str:
        if not self.color_enabled:
            return ""
        return getattr(_Fore, color.upper(), "")

    def _reset(self) -> str:
        return _Style.RESET_ALL if self.color_enabled else ""

    def _wrap(self, text: str, indent: int = 3) -> str:
        width = self._term_width()
        initial_indent = " " * indent
        subsequent_indent = " " * indent
        try:
            return textwrap.fill(text, width=width, initial_indent=initial_indent, subsequent_indent=subsequent_indent)
        except Exception:
            return initial_indent + text

    def _safe_percent(self, num: int, den: int) -> float:
        return (num / den * 100.0) if den else 0.0

    def print_banner(self):
        red = self._c("RED")
        reset = self._reset()
        banner = f"""
{red}                        
            @@@  @@@  @@@  @@@  @@@  @@@  @@@@@@@@       @@@    @@@@@@@@   @@@@@@   
            @@@@ @@@  @@@  @@@  @@@  @@@  @@@@@@@@      @@@@   @@@@@@@@@@  @@@@@@@  
            @@!@!@@@  @@!  @@@  @@!  !@@  @@!          @@!@!   @@!   @@@@      @@@  
            !@!!@!@!  !@!  @!@  !@!  @!!  !@!         !@!!@!   !@!  @!@!@      @!@  
            @!@ !!@!  @!@  !@!  @!@@!@!   @!!!:!     @!! @!!   @!@ @! !@!  @!@!!@   
            !@!  !!!  !@!  !!!  !!@!!!    !!!!!:    !!!  !@!   !@!!!  !!!  !!@!@!   
            !!:  !!!  !!:  !!!  !!: :!!   !!:       :!!:!:!!:  !!:!   !!!      !!:  
            :!:  !:!  :!:  !:!  :!:  !:!  :!:       !:::!!:::  :!:    !:!      :!:  
            ::   ::  ::::: ::   ::  :::   :: ::::       :::   ::::::: ::  :: ::::  
            ::    :    : :  :    :   :::  : :: ::        :::    : : :  :    : : :   
                                                                                                                        
{reset}
        Advanced level 403/401 Bypasser
        """
        print(banner)
        
    def print_target_info(self, target_url: str, profile: Dict[str, Any]):
        cyan, white = self._c("CYAN"), self._c("WHITE")
        reset = self._reset()
        print(f"\n{cyan}[*] Target: {white}{target_url}{reset}")
        waf = profile.get("waf") or {}
        if isinstance(waf, dict) and waf:
            waf_info = ", ".join(f"{name} ({conf:.0%})" for name, conf in waf.items())
            print(self._wrap(f"{cyan}[*] WAF Detection: {white}{waf_info}{reset}", indent=0))

        backend = profile.get("backend") or {}
        if isinstance(backend, dict) and backend:
            backend_info = ", ".join(f"{name} ({conf:.0%})" for name, conf in backend.items())
            print(self._wrap(f"{cyan}[*] Backend: {white}{backend_info}{reset}", indent=0))

        protocol = profile.get("protocol") or {}
        versions = protocol.get("http_versions") or []
        if versions:
            info = ", ".join(versions)
            print(self._wrap(f"{cyan}[*] HTTP Versions: {white}{info}{reset}", indent=0))

    def print_bypass_result(self, result: Dict[str, Any]):
        technique = result.get("technique", "unknown")
        status_code = int(result.get("status_code", 0) or 0)
        url = result.get("url", "N/A")
        payload = result.get("payload", "N/A")

        if 200 <= status_code < 300:
            status_color = self._c("GREEN")
        elif 300 <= status_code < 400:
            status_color = self._c("YELLOW")
        else:
            status_color = self._c("RED")

        cyan, white, reset = self._c("CYAN"), self._c("WHITE"), self._reset()
        print(f"\n{cyan}[+] {white}Bypass Found!{reset}")
        print(self._wrap(f"{cyan}Technique: {white}{technique}{reset}"))
        print(self._wrap(f"{cyan}Status: {status_color}{status_code}{reset}"))
        print(self._wrap(f"{cyan}URL: {white}{url}{reset}"))

        if payload and payload != "N/A":
            print(self._wrap(f"{cyan}Payload: {white}{payload}{reset}"))

        if self.verbose:
            skip = {"technique", "status_code", "url", "payload"}
            for key in sorted(k for k in result.keys() if k not in skip):
                val = result.get(key)
                val_s = str(val)
                if len(val_s) > 1200:
                    val_s = val_s[:1200] + "...(truncated)"
                print(self._wrap(f"{cyan}{key}: {white}{val_s}{reset}"))

    def print_scan_summary(self, results: List[Dict[str, Any]], scan_time: float):
        cyan, green, red, white, reset = self._c("CYAN"), self._c("GREEN"), self._c("RED"), self._c("WHITE"), self._reset()

        total = len(results)
        successful = [r for r in results if 200 <= int(r.get("status_code", 0) or 0) < 400]
        success_count = len(successful)
        success_rate = self._safe_percent(success_count, total)
        bar = cyan + "=" * min(60, self._term_width()) + reset
        print(f"\n{bar}")
        print(f"{cyan}SCAN SUMMARY{reset}")
        print(f"{bar}")
        print(f"{cyan}Total bypass attempts: {white}{total}{reset}")
        print(f"{cyan}Successful bypasses: {(green if success_count else red)}{success_count}{reset}")
        print(f"{cyan}Success rate: {white}{success_rate:.1f}%{reset}")
        print(f"{cyan}Scan duration: {white}{scan_time:.2f} seconds{reset}")

        if success_count:
            print(f"\n{cyan}SUCCESSFUL TECHNIQUES:{reset}")
            items = successful
            if self.sort_success:
                items = sorted(items, key=lambda r: (int(r.get("status_code", 0) or 0), r.get("technique", "")))
            for r in items:
                technique = r.get("technique", "unknown")
                code = int(r.get("status_code", 0) or 0)
                print(self._wrap(f"  {green}✓ {technique} ({code}){reset}", indent=2))

        print(f"{bar}")

    def generate_json_report(self, results: List[Dict[str, Any]], filename: str):
        """Generate a JSON report (UTF-8)."""
        report = {
            "timestamp": datetime.now().isoformat(),
            "results": results,
            "summary": {
                "total_attempts": len(results),
                "successful_bypasses": len([r for r in results if 200 <= int(r.get('status_code', 0) or 0) < 400]),
                "failed_attempts": len([r for r in results if int(r.get('status_code', 0) or 0) >= 400]),
            },
        }

        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"{self._c('GREEN')}[+] JSON report saved to {filename}{self._reset()}")
        except Exception as e:
            logger.error(f"Failed to save JSON report to {filename}: {e}")

    def generate_markdown_report(self, results: List[Dict[str, Any]], filename: str, title: str = "Nuke403 Scan Report"):
        successful = [r for r in results if 200 <= int(r.get("status_code", 0) or 0) < 400]
        total = len(results)
        success_count = len(successful)
        success_rate = self._safe_percent(success_count, total)

        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"# {title}\n\n")
                f.write(f"**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

                f.write("## Summary\n\n")
                f.write(f"- **Total bypass attempts**: {total}\n")
                f.write(f"- **Successful bypasses**: {success_count}\n")
                f.write(f"- **Success rate**: {success_rate:.1f}%\n\n")

                if success_count:
                    f.write("## Successful Bypasses\n\n")
                    if self.sort_success:
                        successful = sorted(successful, key=lambda r: (int(r.get("status_code", 0) or 0), r.get("technique", "")))
                    for r in successful:
                        technique = r.get("technique", "unknown")
                        f.write(f"### {technique}\n\n")
                        f.write(f"- **Status Code**: {int(r.get('status_code', 0) or 0)}\n")
                        f.write(f"- **URL**: `{r.get('url', 'N/A')}`\n")
                        payload = r.get("payload")
                        if payload:
                            payload_str = str(payload)
                            if len(payload_str) > 4000:
                                payload_str = payload_str[:4000] + "...(truncated)"
                            f.write(f"- **Payload**: `{payload_str}`\n")
                        if self.verbose:
                            skip = {"technique", "status_code", "url", "payload"}
                            extras = {k: r[k] for k in r.keys() if k not in skip}
                            if extras:
                                f.write("- **Details**:\n")
                                for k in sorted(extras.keys()):
                                    val = str(extras[k])
                                    if len(val) > 2000:
                                        val = val[:2000] + "...(truncated)"
                                    f.write(f"  - **{k}**: `{val}`\n")
                        f.write("\n")
            print(f"{self._c('GREEN')}[+] Markdown report saved to {filename}{self._reset()}")
        except Exception as e:
            logger.error(f"Failed to save Markdown report to {filename}: {e}")
