import json
import os
import re
import ast
import glob
from pathlib import Path
from typing import Dict, List, Any, Set
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class WAFW00FConsolidatedConverter:
    def __init__(self, wafw00f_plugins_dir: str, output_file: str):
        self.plugins_dir = wafw00f_plugins_dir
        self.output_file = output_file
        self.consolidated_signatures = []
        self.seen_signatures: Set[str] = set()
        
    def convert_all_plugins(self):
        plugin_files = glob.glob(os.path.join(self.plugins_dir, "*.py"))
        
        for plugin_file in plugin_files:
            if plugin_file.endswith('__init__.py'):
                continue
                
            try:
                self.convert_plugin(plugin_file)
            except Exception as e:
                logger.error(f"Failed to convert {plugin_file}: {e}")
        
        self.save_consolidated_signatures()
        
    def convert_plugin(self, plugin_file: str):
        logger.info(f"Converting {os.path.basename(plugin_file)}")
        
        with open(plugin_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        class_name = self.extract_class_name(content)
        waf_name = self.extract_waf_name(content, class_name)
        
        if not waf_name:
            logger.warning(f"Could not extract WAF name from {plugin_file}")
            return
        
        signature_key = f"{self.guess_vendor(waf_name)}_{waf_name}".lower().replace(' ', '_')
        
        if signature_key in self.seen_signatures:
            logger.info(f"Skipping duplicate signature for {waf_name}")
            return
            
        self.seen_signatures.add(signature_key)
        schema = self.extract_schema(content, class_name)
        uris = self.extract_uris(content, class_name)
        
        signature = {
            "name": waf_name,
            "vendor": self.guess_vendor(waf_name),
            "description": f"Converted from WAFW00F {waf_name} plugin",
            "confidence_threshold": 0.8,
            "tests": []
        }
        
        signature["tests"].extend(self.convert_schema_to_tests(schema))
        signature["tests"].extend(self.convert_uris_to_tests(uris))
        self.consolidated_signatures.append(signature)
    
    def save_consolidated_signatures(self):
        os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
        organized_signatures = self.organize_signatures_by_vendor()
        
        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(organized_signatures, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Saved {len(self.consolidated_signatures)} signatures to {self.output_file}")
    
    def organize_signatures_by_vendor(self) -> Dict[str, List[Dict]]:
        organized = {}
        
        for signature in self.consolidated_signatures:
            vendor = signature["vendor"]
            if vendor not in organized:
                organized[vendor] = []
            organized[vendor].append(signature)
        
        return organized

    def extract_class_name(self, content: str) -> str:
        class_pattern = r'class\s+(\w+)\s*\((?:\w+\.)*WAFPlugin\)'
        match = re.search(class_pattern, content)
        return match.group(1) if match else None

    def extract_waf_name(self, content: str, class_name: str) -> str:
        name_pattern = r'name\s*=\s*[\'"]([^\'"]+)[\'"]'
        match = re.search(name_pattern, content)
        if match:
            return match.group(1)
    
        if class_name and class_name.endswith('Plugin'):
            return class_name[:-6]
        
        return None

    def extract_schema(self, content: str, class_name: str) -> List[Any]:
        init_pattern = rf'def\s+__init__\s*\([^)]*\)\s*:.*?self\.schema\s*=\s*(\[.*?\])'
        match = re.search(init_pattern, content, re.DOTALL)
        
        if not match:
            schema_pattern = rf'self\.schema\s*=\s*(\[.*?\])'
            match = re.search(schema_pattern, content, re.DOTALL)
        
        if match:
            try:
                schema_str = match.group(1)
                schema_str = re.sub(r'#.*?$', '', schema_str, flags=re.MULTILINE)
                schema_str = schema_str.replace('\n', ' ') 
                tree = ast.parse(schema_str, mode='eval')
                return ast.literal_eval(tree.body)
            except (SyntaxError, ValueError) as e:
                logger.warning(f"Failed to parse schema: {e}")
        
        return []

    def extract_uris(self, content: str, class_name: str) -> List[str]:
        uri_pattern = r'self\.(?:uri|path)\s*=\s*[\'"]([^\'"]+)[\'"]'
        match = re.search(uri_pattern, content)
        return [match.group(1)] if match else []

    def guess_vendor(self, waf_name: str) -> str:
        vendor_map = {
            'cloudflare': 'Cloudflare',
            'akamai': 'Akamai',
            'aws': 'Amazon',
            'azure': 'Microsoft',
            'barracuda': 'Barracuda',
            'citrix': 'Citrix',
            'f5': 'F5',
            'fortinet': 'Fortinet',
            'imperva': 'Imperva',
            'sucuri': 'Sucuri',
            'wordfence': 'Wordfence'
        }
        
        for key, vendor in vendor_map.items():
            if key in waf_name.lower():
                return vendor
        
        return waf_name

    def convert_schema_to_tests(self, schema: List[Any]) -> List[Dict[str, Any]]:
        tests = []
        
        for item in schema:
            if not isinstance(item, (list, tuple)) or len(item) < 2:
                continue
                
            match_type = item[0]
            match_args = item[1:]
            
            test = None
            
            if match_type == 'headers':
                for header_name, pattern in match_args:
                    test = {
                        "type": "passive",
                        "category": "header",
                        "path": f"header::{header_name.lower()}",
                        "pattern": pattern,
                        "score": 0.7
                    }
                    tests.append(test)
                    
            elif match_type == 'cookies':
                for cookie_name, pattern in match_args:
                    test = {
                        "type": "passive",
                        "category": "cookie",
                        "path": "header::set-cookie",
                        "pattern": f"{cookie_name}.*{pattern}",
                        "score": 0.6
                    }
                    tests.append(test)
                    
            elif match_type == 'code':
                for status_code in match_args:
                    test = {
                        "type": "passive",
                        "category": "code",
                        "path": "response::code",
                        "pattern": str(status_code),
                        "score": 0.5
                    }
                    tests.append(test)
                    
            elif match_type == 'content':
                for pattern in match_args:
                    test = {
                        "type": "passive",
                        "category": "body",
                        "path": "response::body",
                        "pattern": pattern,
                        "score": 0.8
                    }
                    tests.append(test)
        
        return tests

    def convert_uris_to_tests(self, uris: List[str]) -> List[Dict[str, Any]]:
        """Convert URIs to active tests."""
        tests = []
        malicious_payloads = [
            "../../etc/passwd",
            "<script>alert(1)</script>",
            "' OR 1=1--",
            "exec(char(94+94+94))"
        ]
        
        for uri in uris:
            for payload in malicious_payloads:
                test = {
                    "type": "active",
                    "category": "body",
                    "path": "response::body",
                    "pattern": "blocked|forbidden|denied",
                    "payload": f"{uri}/{payload}",
                    "match": "any",
                    "score": 0.7
                }
                tests.append(test)
                
        return tests

    def save_signature(self, signature: Dict[str, Any]):
        safe_name = re.sub(r'[^\w\-_]', '_', signature["name"]).lower()
        output_file = os.path.join(self.output_dir, f"{safe_name}.json")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump([signature], f, indent=2, ensure_ascii=False)
        
        logger.info(f"Saved signature for {signature['name']} to {output_file}")

def main():
    wafw00f_plugins_dir = input("Enter path to WAFW00F plugins directory: ").strip()
    
    if not os.path.isdir(wafw00f_plugins_dir):
        logger.error(f"Directory not found: {wafw00f_plugins_dir}")
        return
    
    output_dir = "../core/profiler/signatures"
    os.makedirs(output_dir, exist_ok=True)
    converter = WAFW00FConverter(wafw00f_plugins_dir, output_dir)
    converter.convert_all_plugins()
    
    logger.info("Conversion completed!")

if __name__ == "__main__":
    main()