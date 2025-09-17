import argparse
import asyncio
import logging
import sys
import signal
from typing import Dict, List, Optional
from utils.logger import setup_logger, get_logger
from utils.helpers import load_config, normalize_url, is_valid_url
from engines.scanner import NuclearScanner
from engines.exploit_generator import ExploitGenerator
from utils.report_generator import ReportGenerator

class Nuke403:
    def __init__(self):
        self.config = {}
        self.scanner = None
        self.reporter = None
        self.exploit_generator = None
        self.logger = get_logger()
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        self.logger.info("Received shutdown signal, terminating...")
        if self.scanner:
            asyncio.create_task(self.scanner.http_client.close())
        sys.exit(0)
        
    def print_banner(self):
        use_color = self.config.get('color_output', True)
        red = "\033[91m" if use_color else ""
        reset = "\033[0m" if use_color else ""
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
    
    def parse_arguments(self):
        parser = argparse.ArgumentParser(
            description="Nuke403: Advanced 403/401 Bypass tool",
            epilog="Example: nuke403 -u https://target.com/admin -o results.json -v"
        )
        target_group = parser.add_argument_group("Target Options")
        target_group.add_argument("-u", "--url", required=True, help="Target URL to test")
        target_group.add_argument("-f", "--file", help="File containing multiple URLs")
        output_group = parser.add_argument_group("Output Options")
        output_group.add_argument("-o", "--output", help="Output file for results")
        output_group.add_argument("-F", "--format", choices=["json", "markdown", "text"], default="text", help="Output format")
        output_group.add_argument("--no-color", action="store_true", help="Disable colored output")
        scan_group = parser.add_argument_group("Scan Options")
        scan_group.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads")
        scan_group.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds")
        scan_group.add_argument("--max-retries", type=int, default=2, help="Maximum retry attempts for failed requests")
        scan_group.add_argument("--rate-limit", type=int, default=5, help="Maximum requests per second")
        attack_group = parser.add_argument_group("Attack Options")
        attack_group.add_argument("--no-path", action="store_true", help="Disable path-based attacks")
        attack_group.add_argument("--no-header", action="store_true", help="Disable header-based attacks")
        attack_group.add_argument("--no-protocol", action="store_true", help="Disable protocol-based attacks")
        attack_group.add_argument("--no-ai", action="store_true", help="Disable AI-guided attacks")
        config_group = parser.add_argument_group("Configuration Options")
        config_group.add_argument("-c", "--config", help="Configuration file")
        config_group.add_argument("--user-agent", help="Custom User-Agent string")
        config_group.add_argument("--proxy", help="Proxy server (http://host:port)")
        general_group = parser.add_argument_group("General Options")
        general_group.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
        general_group.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (only errors)")
        general_group.add_argument("--version", action="version", version="Nuke403 v1.0.0")
        return parser.parse_args()
    
    def setup_configuration(self, args):
        if args.config:
            self.config = load_config(args.config)
        else:
            self.config = load_config("config/settings.yaml")
        
        cli_config = {
            'target_url': args.url,
            'output_file': args.output,
            'output_format': args.format,
            'threads': args.threads,
            'timeout': args.timeout,
            'max_retries': args.max_retries,
            'rate_limit': args.rate_limit,
            'path_attacks': not args.no_path,
            'header_attacks': not args.no_header,
            'protocol_attacks': not args.no_protocol,
            'ai_enabled': not args.no_ai,
            'user_agent': args.user_agent,
            'proxy': args.proxy,
            'color_output': not args.no_color,
            'verbose': args.verbose,
            'quiet': args.quiet
        }
        self.config.update({k: v for k, v in cli_config.items() if v is not None})
        
        if not is_valid_url(self.config['target_url']):
            self.logger.error(f"Invalid target URL: {self.config['target_url']}")
            sys.exit(1)
        self.config['target_url'] = normalize_url(self.config['target_url'])
    
    def setup_logging(self):
        log_level = logging.INFO
        if self.config.get('verbose'):
            log_level = logging.DEBUG
        if self.config.get('quiet'):
            log_level = logging.ERROR
        setup_logger(level=log_level)
        self.logger = get_logger()
    
    async def run_scan(self):
        try:
            self.scanner = NuclearScanner(self.config)
            self.reporter = ReportGenerator(self.config)
            self.exploit_generator = ExploitGenerator()
            self.print_banner()
            
            self.logger.info(f"Starting scan against: {self.config['target_url']}")
            results = await self.scanner.scan(self.config['target_url'])
            
            if self.config.get('output_file'):
                if self.config.get('output_format') == 'json':
                    self.reporter.generate_json_report(results, self.config['output_file'])
                elif self.config.get('output_format') == 'markdown':
                    self.reporter.generate_markdown_report(results, self.config['output_file'])
            
            self.reporter.print_scan_summary(results, 0) 
            
            successful_bypasses = [r for r in results if 200 <= r.get('status_code', 0) < 400]
            if successful_bypasses:
                self.logger.info("Generating exploit chains...")
                exploit_chain = self.exploit_generator.generate_exploit_chain(successful_bypasses)
                for i, exploit in enumerate(exploit_chain):
                    self.logger.info(f"Exploit {i+1}: {exploit.get('description')}")
                    poc_script = self.exploit_generator.generate_poc_script(exploit, 'python')
                    self.logger.debug(f"PoC Script:\n{poc_script}")
            return len(successful_bypasses) > 0
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            if self.config.get('verbose'):
                self.logger.exception("Detailed error traceback:")
            return False
    
    async def run_multiple_targets(self, target_file: str):
        try:
            with open(target_file, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            self.logger.info(f"Found {len(targets)} targets in file")
            successful_scans = 0
            for target in targets:
                if not is_valid_url(target):
                    self.logger.warning(f"Skipping invalid URL: {target}")
                    continue
                self.config['target_url'] = normalize_url(target)
                self.logger.info(f"Scanning target: {target}")
                if await self.run_scan():
                    successful_scans += 1
            self.logger.info(f"Completed multi-target scan. Successful bypasses in {successful_scans}/{len(targets)} targets.")
        except FileNotFoundError:
            self.logger.error(f"Target file not found: {target_file}")
            return False
        except Exception as e:
            self.logger.error(f"Multi-target scan failed: {e}")
            return False
    
    async def close(self):
        if self.scanner:
            await self.scanner.http_client.close()

async def main():
    nuke = Nuke403()
    args = nuke.parse_arguments()
    nuke.setup_configuration(args)
    nuke.setup_logging()
    success = False
    try:
        if args.file:
            success = await nuke.run_multiple_targets(args.file)
        else:
            success = await nuke.run_scan()
    finally:
        await nuke.close()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    if sys.version_info < (3, 7):
        print("Nuke403 requires Python 3.7 or higher")
        sys.exit(1)
    asyncio.run(main())
