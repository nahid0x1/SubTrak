import asyncio
import aiohttp
import json
import argparse
import logging
import re
import ssl
import sys
import time
import random
import base64
import hashlib
import socket
import os
import shutil
import subprocess
from datetime import datetime
from typing import Set, List, Optional, Dict, TextIO
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

# Python 2.x and 3.x compatibility check
if sys.version > '3':
    import urllib.parse as urlparse
else:
    import urlparse

# beautifulsoup4 is required for JS grabbing
try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[-] BeautifulSoup4 is not installed. Please install it using: pip install beautifulsoup4")
    sys.exit(1)

# PyYAML is required for resume functionality
try:
    import yaml
except ImportError:
    print("[-] PyYAML is not installed. Please install it for resume functionality: pip install pyyaml")
    sys.exit(1)

# -------------------------------------------------------------------
# User Configuration Area
# -------------------------------------------------------------------

# --- TELEGRAM BOT CONFIGURATION ---
TELEGRAM_CONFIG = {
    "enabled": True,
    "api_token": "",
    "chat_id": ""
}

# --- API KEY CONFIGURATION ---
# --- Format ["api_key"]
API_KEYS = {
    "bevigil": [],
    "binaryedge": [],
    "bufferover": [],
    "builtwith": [],
    "c99": [],
    "censys": [],
    "certspotter": [],
    "chaos": [],
    "chaospublicrecon": [],
    "chinaz": [],
    "dnsdumpster": [],
    "dnsrepo": [],
    "facebook": [],
    "fofa": [],
    "fullhunt": [],
    "github": [],
    "hunter": [],
    "intelx": [],
    "leakix": [],
    "netlas": [],
    "quake": [],
    "redhuntlabs": [],
    "robtex": [],
    "securitytrails": [],
    "shodan": [],
    "spyse": [],
    "threatbook": [],
    "virustotal": [],
    "whoisxmlapi": [],
    "zoomeyeapi": [],
    "digitalyama": [],
    "urlscan": [],
}

# --- Banner Function ---
def print_banner():
    """Prints a welcome banner."""
    banner = r"""

 __       _    _____           _    
/ _\_   _| |__/__   \_ __ __ _| | __
\ \| | | | '_ \ / /\/ '__/ _` | |/ /
_\ \ |_| | |_) / /  | | | (_| |   < 
\__/\__,_|_.__/\/   |_|  \__,_|_|\_\ v1
                                    
    """
    credit = "                     ~ develop by nahid0x1 ~"
    print(banner)
    print(credit)
    print("-" * 60)

# --- TelegramNotifier Class ---
class TelegramNotifier:
    """Manages sending updates and handling commands via Telegram."""
    def __init__(self, config: Dict, session: aiohttp.ClientSession):
        self.enabled = config.get("enabled", False)
        self.api_token = config.get("api_token")
        self.chat_id = config.get("chat_id")
        self.session = session
        self.message_id: Optional[int] = None
        self.last_update_text: str = ""
        self.last_update_time: float = 0.0
        self.scan_start_time: float = time.time()
        self.last_update_id: int = 0
        if self.enabled and (not self.api_token or not self.chat_id):
            print("[-] Telegram notifications enabled, but token or chat_id is missing.", file=sys.stderr)
            self.enabled = False
    async def send_simple_message(self, chat_id: str, text: str):
        if not self.enabled: return
        url = f"https://api.telegram.org/bot{self.api_token}/sendMessage"
        payload = {"chat_id": chat_id, "text": text}
        try:
            async with self.session.post(url, json=payload) as response:
                if response.status != 200:
                    logging.error(f"Telegram simple message failed ({response.status}): {await response.text()}")
        except aiohttp.ClientError as e:
            logging.error(f"Failed to send simple message to Telegram: {e}")
    async def _handle_update(self, update: Dict):
        if 'message' not in update or 'text' not in update['message']: return
        message = update['message']
        chat_id = message['chat']['id']
        command = message['text'].strip()
        if command == '/ping':
            print(f"\n[+] Received /ping command from chat ID {chat_id}. Responding...")
            await self.send_simple_message(str(chat_id), "Yes, I'm alive!🫣")
    async def start_listener(self):
        if not self.enabled: return
        print("[*] Telegram command listener started.")
        url = f"https://api.telegram.org/bot{self.api_token}/getUpdates"
        try:
            async with self.session.get(url, params={'offset': -1, 'timeout': 1}, timeout=5): pass
        except Exception: pass
        while True:
            try:
                params = {'timeout': 30, 'offset': self.last_update_id + 1, 'allowed_updates': ['message']}
                async with self.session.get(url, params=params, timeout=35) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get("ok"):
                            for update in data.get("result", []):
                                if 'update_id' in update:
                                    self.last_update_id = max(self.last_update_id, update['update_id'])
                                    await self._handle_update(update)
                    elif response.status == 409:
                        logging.warning("Telegram conflict (409). Retrying...")
                        await asyncio.sleep(30)
                    else:
                        logging.error(f"Telegram getUpdates error ({response.status}): {await response.text()}")
                        await asyncio.sleep(15)
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logging.error(f"Telegram listener connection error: {e}. Retrying...")
                await asyncio.sleep(10)
            except Exception as e:
                logging.error(f"Unexpected error in Telegram listener: {e}")
                await asyncio.sleep(10)
    def _format_duration(self, seconds: float) -> str:
        s = int(seconds)
        h, s = divmod(s, 3600)
        m, s = divmod(s, 60)
        return f"{h:01}:{m:02}:{s:02}"
    def format_message(self, state: Dict) -> str:
        elapsed_time = time.time() - self.scan_start_time
        duration_str = self._format_duration(elapsed_time)
        scan_status = state.get('status', 'Running...')
        mode = state.get('mode', 'Normal')
        phase = f" ({state.get('phase')})" if state.get('phase') else ""
        target = state.get('current_domain', '...')
        completed_domains = state.get('completed_domains', 0)
        total_domains_in_phase = state.get('total_domains_in_phase', 1)
        target_progress = f"({completed_domains + 1}/{total_domains_in_phase})"
        header = f"🚀 *{mode} Scan {scan_status}{phase}*\n"
        header += f"   └─ Target: `{target}` {target_progress}\n\n"
        source_details = ""
        source_status_dict = state.get('source_status', {})
        if source_status_dict:
            source_details += "*Sources Status:*\n"
            for name, status in sorted(source_status_dict.items()):
                status_short = (status[:30] + '..') if len(status) > 32 else status
                source_details += f"`- {name:<18}: {status_short}`\n"
            source_details += "\n"
        completed_sources = state.get('completed_sources', 0)
        num_sources = state.get('num_sources', 1)
        source_progress = (completed_sources / num_sources) * 100 if num_sources > 0 else 0
        progress_bar_length = 20
        filled_length = int(progress_bar_length * source_progress // 100)
        source_bar = '█' * filled_length + '─' * (progress_bar_length - filled_length)
        progress_line = f"*Phase Progress:* `[{source_bar}] {source_progress:.1f}%`\n"
        summary_line = f"*Total Unique Subs:* `{state.get('sub_count', 0)}`\n*Elapsed Time:* `{duration_str}`"
        endpoint_section = ""
        if state.get('endpoint_scan_active', False):
            endpoint_status = state.get('endpoint_status', 'Running...')
            endpoint_section = (f"\n\n--- *Endpoint Scan ({endpoint_status})* ---\n*Unique URLs:* `{state.get('url_count', 0)}`\n*Unique JS Files:* `{state.get('js_count', 0)}`")
        return header + source_details + progress_line + summary_line + endpoint_section
    async def send_or_update_message(self, state: Dict, force: bool = False):
        if not self.enabled: return
        current_time = time.time()
        if not force and (current_time - self.last_update_time) < 2.5: return
        message_text = self.format_message(state)
        if not force and message_text == self.last_update_text: return
        base_url = f"https://api.telegram.org/bot{self.api_token}/"
        payload = {"chat_id": self.chat_id, "text": message_text, "parse_mode": "Markdown"}
        url = base_url + ("editMessageText" if self.message_id else "sendMessage")
        if self.message_id: payload["message_id"] = self.message_id
        try:
            async with self.session.post(url, json=payload) as response:
                if response.status == 200:
                    self.last_update_text, self.last_update_time = message_text, current_time
                    if not self.message_id:
                        self.message_id = (await response.json()).get('result', {}).get('message_id')
                elif "message is not modified" not in await response.text():
                    logging.error(f"Telegram API Error ({response.status}): {await response.text()}")
        except aiohttp.ClientError as e:
            logging.error(f"Failed to communicate with Telegram API: {e}")

# --- UIManager Class ---
class UIManager:
    """Manages console output."""
    def __init__(self, sources: List[str], telegram_notifier: TelegramNotifier, scan_state: Dict, output_file: Optional[TextIO] = None):
        self.sources_names = sorted(sources)
        self.telegram_notifier = telegram_notifier
        self.scan_state = scan_state
        self.output_file = output_file
        self.lock = asyncio.Lock()
        if sys.stdout.isatty():
            self.term_height = len(self.sources_names) + 7
            sys.stdout.write("\n" * self.term_height)
            sys.stdout.write("\033[?25l")
    async def update_state_and_notify(self, updates: Dict, force_notify: bool = False):
        async with self.lock:
            self.scan_state.update(updates)
            if sys.stdout.isatty(): self._render()
            await self.telegram_notifier.send_or_update_message(self.scan_state, force=force_notify)
    def _render(self):
        sys.stdout.write(f"\033[{self.term_height}A")
        mode = self.scan_state.get('mode', 'Normal')
        status = self.scan_state.get('status', 'Running...')
        phase = f" ({self.scan_state.get('phase', '')})" if self.scan_state.get('phase') else ""
        domain = self.scan_state.get('current_domain', '...')
        completed = self.scan_state.get('completed_domains', 0)
        total_domains_in_phase = self.scan_state.get('total_domains_in_phase', 1)
        domain_progress_str = f"({completed + 1}/{total_domains_in_phase})"
        sys.stdout.write("\033[K" + f"🚀 Scan Mode: {mode} | Status: {status}{phase}\n")
        sys.stdout.write("\033[K" + f"   └─ Target: {domain} {domain_progress_str}\n")
        sys.stdout.write("\033[K\n")
        for name in self.sources_names:
            status_msg = self.scan_state.get('source_status', {}).get(name, "Pending...")
            sys.stdout.write("\033[K" + f"  [{name: <20}] {status_msg}\n")
        sys.stdout.write("\033[K" + "-" * 60 + "\n")
        completed_src, total_src = self.scan_state.get('completed_sources', 0), self.scan_state.get('num_sources', 1)
        source_progress = (completed_src / total_src) * 100 if total_src > 0 else 0
        progress_bar_length = 40
        filled_length = int(progress_bar_length * source_progress // 100)
        source_bar = '█' * filled_length + '─' * (progress_bar_length - filled_length)
        sys.stdout.write("\033[K" + f"  Phase Progress: [{source_bar}] {source_progress:.2f}%\n")
        total_completed_domains = len(self.scan_state.get('completed_domains_list', []))
        total_domains = len(self.scan_state.get('total_domains_list', []))
        overall_progress = (total_completed_domains / total_domains) * 100 if total_domains > 0 else 0
        sys.stdout.write("\033[K" + f"  Overall Domains Scanned: {total_completed_domains}/{total_domains} ({overall_progress:.2f}%)\n")
        elapsed_time = time.time() - self.telegram_notifier.scan_start_time
        sys.stdout.write("\033[K" + f"  Total Unique Subs: {self.scan_state.get('sub_count', 0)} | Elapsed: {elapsed_time:.2f}s\n")
        sys.stdout.flush()
    def finish(self):
        if sys.stdout.isatty():
            self._render()
            sys.stdout.write(f"\033[{self.term_height}B")
            sys.stdout.write("\033[?25h")
            print()

# --- EndpointGrabber Class ---
class EndpointGrabber:
    def __init__(self, subdomains: Set[str], output_file_path: str, js_output_file_path: str, max_workers: int = 10, telegram_notifier: Optional[TelegramNotifier] = None, scan_state: Optional[Dict] = None):
        self.subdomains, self.output_file_path, self.js_output_file_path = list(subdomains), output_file_path, js_output_file_path
        self.max_workers, self.telegram_notifier, self.scan_state = max_workers, telegram_notifier, scan_state if scan_state is not None else {}
        self.found_endpoints, self.found_js_files, self.lock = set(), set(), asyncio.Lock()
        self.external_tools, self.internal_sources = self._find_installed_tools(), ["otx_api", "urlscan_api", "js_grabber"]
        if not self.external_tools and not self.internal_sources:
             print("\n[-] No endpoint/JS grabbing tools available."); sys.exit(1)
        info_str = []
        if self.external_tools: info_str.append(f"{len(self.external_tools)} external tools ({', '.join(self.external_tools)})")
        if self.internal_sources:
            info_str.append(f"{len([s for s in self.internal_sources if s != 'js_grabber'])} API sources and a built-in JS grabber")
        print(f"\n[*] Endpoint/JS Grabber initialized with " + " and ".join(info_str))
    def _find_installed_tools(self) -> List[str]:
        return [tool for tool in ["gauplus", "waybackurls", "hakrawler"] if shutil.which(tool)]
    def _run_tool_on_subdomain(self, subdomain: str) -> tuple[str, Set[str]]:
        endpoints = set()
        for tool in self.external_tools:
            try:
                url = 'https://' + subdomain if not subdomain.startswith(('http://', 'https://')) else subdomain
                if tool == "gauplus": cmd = ["gauplus", "-t", "10", subdomain]
                elif tool == "waybackurls": cmd = ["waybackurls", subdomain]
                elif tool == "hakrawler": cmd = ["hakrawler", "-d", "2", "-u", "all", "-url", url]
                else: continue
                proc = subprocess.run(cmd, capture_output=True, text=True, check=False, encoding='utf-8', errors='ignore')
                if proc.returncode == 0 and proc.stdout:
                    endpoints.update(line for line in proc.stdout.strip().split('\n') if line)
            except Exception as e: logging.error(f"Error running {tool} on {subdomain}: {e}")
        return 'endpoint', endpoints
    async def _fetch_otx_endpoints(self, sub: str, sess: aiohttp.ClientSession) -> tuple[str, Set[str]]:
        found, page = set(), 1
        url_tmpl = f"https://otx.alienvault.com/api/v1/indicators/hostname/{sub}/url_list?limit=200&page={{page}}"
        while True:
            try:
                async with sess.get(url_tmpl.format(page=page), timeout=aiohttp.ClientTimeout(total=3)) as r:
                    if r.status != 200: break
                    data = await r.json(content_type=None)
                    found.update(item['url'] for item in data.get('url_list', []) if item.get('url'))
                    if not data.get('has_next', False) or not data.get('url_list', []): break
                    page += 1
            except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): break
        return 'endpoint', found
    async def _fetch_urlscan_endpoints(self, sub: str, sess: aiohttp.ClientSession) -> tuple[str, Set[str]]:
        found, headers, after = set(), {}, None
        if key := API_KEYS.get('urlscan', [None])[0]: headers['API-Key'] = key
        while True:
            try:
                url = f"https://urlscan.io/api/v1/search/?q=domain:{sub}&size=100"
                if after: url += f"&search_after={after}"
                async with sess.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=3)) as r:
                    if r.status in [429, 400]: break
                    data = await r.json(content_type=None)
                    results = data.get('results', [])
                    found.update(res['page']['url'] for res in results if res.get('page', {}).get('url'))
                    if data.get('has_more') and results: after = ",".join(map(str, results[-1]['sort']))
                    else: break
            except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): break
        return 'endpoint', found
    async def _fetch_js_from_subdomain(self, sub: str, sess: aiohttp.ClientSession) -> tuple[str, Set[str]]:
        js, url = set(), 'https://' + sub if not sub.startswith(('http://', 'https://')) else sub
        try:
            # Note: A 3-second timeout is too aggressive for fetching a full webpage. We use the session's default timeout here.
            async with sess.get(url, allow_redirects=True) as r:
                if r.status != 200: return 'js', js
                soup = BeautifulSoup(await r.text(encoding='utf-8', errors='ignore'), 'html.parser')
                regex = re.compile(r'[\'"]([a-zA-Z0-9_./-]+\.js)[\'"]')
                paths = [tag.get(a) for tag in soup.find_all('script') for a in ['src', 'data-src'] if tag.get(a)]
                for tag in soup.find_all('script'):
                    if not tag.get('src'): paths.extend(regex.findall(tag.string or ''))
                paths.extend(tag.get('data-script-src') for tag in soup.find_all('div') if tag.get('data-script-src'))
                for path in paths: js.add(urlparse.urljoin(str(r.url), path))
        except (aiohttp.ClientError, asyncio.TimeoutError): pass
        except Exception as e: logging.error(f"Error grabbing JS from {sub}: {e}")
        return 'js', js
    async def grab_endpoints(self):
        print(f"\n[+] Starting endpoint and JS grabbing for {len(self.subdomains)} subdomains...")
        if self.telegram_notifier:
            self.scan_state.update({'endpoint_scan_active': True, 'endpoint_status': 'Running...'})
            await self.telegram_notifier.send_or_update_message(self.scan_state, force=True)
        tasks = []
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=40), connector=aiohttp.TCPConnector(ssl=False)) as session:
            for sub in self.subdomains:
                tasks.extend([self._fetch_otx_endpoints(sub, session), self._fetch_urlscan_endpoints(sub, session), self._fetch_js_from_subdomain(sub, session)])
            if self.external_tools:
                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    loop = asyncio.get_running_loop()
                    tasks.extend(loop.run_in_executor(executor, self._run_tool_on_subdomain, sub) for sub in self.subdomains)
                    await self._process_tasks(tasks)
            else: await self._process_tasks(tasks)
        with open(self.output_file_path, 'w', encoding='utf-8') as f: f.write('\n'.join(sorted(list(self.found_endpoints))) + '\n')
        with open(self.js_output_file_path, 'w', encoding='utf-8') as f_js: f_js.write('\n'.join(sorted(list(self.found_js_files))) + '\n')
        print(f"\n[+] Grabbing finished in {time.time() - self.telegram_notifier.scan_start_time:.2f} seconds.")
        print(f"[+] Found {len(self.found_endpoints)} URLs and {len(self.found_js_files)} JS files.")
        if self.telegram_notifier:
            self.scan_state['endpoint_status'] = 'Complete'
            await self.telegram_notifier.send_or_update_message(self.scan_state, force=True)
    async def _process_tasks(self, tasks: List):
        for i, future in enumerate(asyncio.as_completed(tasks)):
            updated = False
            try:
                res_type, res_set = await future
                if res_set:
                    async with self.lock:
                        if res_type == 'endpoint' and len(res_set - self.found_endpoints) > 0:
                            self.found_endpoints.update(res_set); self.scan_state['url_count'] = len(self.found_endpoints); updated = True
                        elif res_type == 'js' and len(res_set - self.found_js_files) > 0:
                            self.found_js_files.update(res_set); self.scan_state['js_count'] = len(self.found_js_files); updated = True
            except Exception as e: logging.error(f"A task failed in _process_tasks: {e}")
            if updated and self.telegram_notifier: await self.telegram_notifier.send_or_update_message(self.scan_state)
            progress = ((i + 1) / len(tasks)) * 100
            sys.stdout.write(f"\r[*] Progress: {i+1}/{len(tasks)} ({progress:.2f}%) | Found: {len(self.found_endpoints)} URLs, {len(self.found_js_files)} JS")
            sys.stdout.flush()

# --- Helper Functions & Source Base Class ---
def clean_subdomain(s: str) -> str:
    s = s.lower().strip().replace('*.', ''); s = s.split("://")[1] if "://" in s else s; return s.split("/")[0].split(":")[0]
class Source:
    def __init__(self, name: str, needs_key: bool = False): self.name, self.needs_key, self.api_keys, self.subdomains = name.lower(), needs_key, [], set()
    def add_keys(self, keys: List[str]): self.api_keys = keys
    def get_random_key(self) -> Optional[str]: return random.choice(self.api_keys) if self.api_keys else None
    async def find(self, domain: str, session: aiohttp.ClientSession) -> Set[str]: raise NotImplementedError

# --- All Source Classes (Full List) ---
# ... [No changes needed in any of the Source classes] ...
class OpenSSL_SAN(Source):
    def __init__(self): super().__init__("openssl_san")
    def _get_cert_sans(self, domain: str) -> Set[str]:
        found_domains, context = set(), ssl.create_default_context()
        try:
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as sslsock: cert = sslsock.getpeercert()
            if 'subjectAltName' in cert:
                for san_type, san_value in cert['subjectAltName']:
                    if san_type == 'DNS': found_domains.add(clean_subdomain(san_value))
            if 'subject' in cert:
                for rdn_seq in cert['subject']:
                    for rdn in rdn_seq:
                        if rdn[0] == 'commonName': found_domains.add(clean_subdomain(rdn[1]))
        except (socket.gaierror, socket.timeout, ConnectionRefusedError, ssl.SSLError, OSError): return set()
        return found_domains
    async def find(self, domain: str, session: aiohttp.ClientSession) -> Set[str]:
        try:
            subdomains = await asyncio.get_running_loop().run_in_executor(None, self._get_cert_sans, domain)
            return {sub for sub in subdomains if sub.endswith(f".{domain}") and sub != domain}
        except Exception: return set()
class SearchEngine(Source):
    def __init__(self, name: str, base_url: str, query_template: str, page_increment: int, max_pages: int, max_domains_in_query: int):
        super().__init__(name)
        self.base_url, self.query_template, self.page_increment, self.max_pages, self.max_domains_in_query = base_url, query_template, page_increment, max_pages, max_domains_in_query
    def generate_query(self, domain: str) -> str:
        if self.subdomains:
            found_str = ' -site:'.join(list(self.subdomains)[:self.max_domains_in_query])
            return self.query_template.format(domain=domain, found=found_str)
        return f"site:{domain} -site:www.{domain}"
    async def extract_domains(self, resp_text: str, domain: str) -> Set[str]: raise NotImplementedError
    async def find(self, domain: str, session: aiohttp.ClientSession) -> Set[str]:
        page_num, retries = 0, 0
        while True:
            if self.max_pages > 0 and page_num >= self.max_pages: break
            encoded_query = urlparse.quote_plus(self.generate_query(domain))
            url = self.base_url.format(query=encoded_query, page=page_num)
            try:
                async with session.get(url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=3)) as r:
                    if r.status != 200: break
                    newly_found = await self.extract_domains(await r.text(), domain)
                    if not newly_found:
                        if (retries := retries + 1) >= 3: break
                    else:
                        retries, initial_count = 0, len(self.subdomains)
                        self.subdomains.update(newly_found)
                        if len(self.subdomains) == initial_count and (retries := retries + 1) >= 3: break
            except Exception: break
            page_num += self.page_increment
            await asyncio.sleep(random.uniform(2, 4))
        return self.subdomains
class Google(SearchEngine):
    def __init__(self): super().__init__("google", "https://google.com/search?q={query}&start={page}&filter=0", "site:{domain} -www.{domain} -{found}", 10, 200, 10)
    async def extract_domains(self, t: str, d: str) -> Set[str]:
        f, regex = set(), re.compile(r'<cite.*?>(.*?)<\/cite>')
        try:
            for l in regex.findall(t):
                if (s := clean_subdomain(re.sub('<span.*?>', '', l))).endswith(f".{d}"): f.add(s)
        except Exception: pass
        return f
class Yahoo(SearchEngine):
    def __init__(self): super().__init__("yahoo", "https://search.yahoo.com/search?p={query}&b={page}", "site:{domain} -domain:www.{domain} -domain:{found}", 10, 200, 70)
    async def extract_domains(self, t: str, d: str) -> Set[str]:
        f, regex = set(), re.compile(r'<span class=" fz-.*? fw-m fc-12th wr-bw.*?">(.*?)</span>')
        try:
            for l in regex.findall(t):
                if (s := clean_subdomain(re.sub(r"<(/)?b>", "", l))).endswith(f".{d}"): f.add(s)
        except Exception: pass
        return f
class Bing(SearchEngine):
    def __init__(self): super().__init__("bing", 'https://www.bing.com/search?q={query}&go=Submit&first={page}', 'domain:{domain} -www.{domain} -{found}', 10, 200, 30)
    async def extract_domains(self, t: str, d: str) -> Set[str]:
        f, regex = set(), re.compile(r'<cite>(.*?)</cite>')
        try:
            for l in regex.findall(t):
                if (s := clean_subdomain(re.sub('<.*?>', '', l))).endswith(f".{d}"): f.add(s)
        except Exception: pass
        return f
class Ask(SearchEngine):
    def __init__(self): super().__init__("ask", 'http://www.ask.com/web?q={query}&page={page}', 'site:{domain} -www.{domain} -{found}', 1, 100, 10)
    async def extract_domains(self, t: str, d: str) -> Set[str]:
        f, regex = set(), re.compile(r'<p class="web-result-url">(.*?)</p>')
        try:
            for l in regex.findall(t):
                if (s := clean_subdomain(l)).endswith(f".{d}"): f.add(s)
        except Exception: pass
        return f
class Baidu(SearchEngine):
    def __init__(self): super().__init__("baidu", 'https://www.baidu.com/s?pn={page}&wd={query}', 'site:{domain} -site:www.{domain} -site:{found}', 10, 760, 2)
    async def extract_domains(self, t: str, d: str) -> Set[str]:
        f, regex = set(), re.compile(r'<a.*?class="c-showurl".*?>(.*?)</a>')
        try:
            for l in regex.findall(t):
                if (s := clean_subdomain(re.sub('<.*?>', '', l))).endswith(f".{d}"): f.add(s)
        except Exception: pass
        return f
class Netcraft(Source):
    def __init__(self): super().__init__("netcraft")
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        f, base = set(), 'https://searchdns.netcraft.com'
        query = f"{base}/?restriction=site+ends+with&host={d}"
        try:
            async with s.get(base, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=3)) as r1:
                if 'set-cookie' not in r1.headers: return f
                cookie = r1.headers['set-cookie'].split(';')[0].split('=')[1]
                sha1 = hashlib.sha1(urlparse.unquote(cookie).encode('utf-8')).hexdigest()
                cookies = {'netcraft_js_verification_response': sha1}
                next_url = query
                while next_url:
                    async with s.get(next_url, cookies=cookies, timeout=aiohttp.ClientTimeout(total=3)) as r2:
                        if r2.status != 200: break
                        text = await r2.text()
                        for link in re.findall(r'<a class="results-table__host" href="(.*?)"', text):
                            if (sub := urlparse.urlparse(link).netloc) and sub.endswith(f".{d}"): f.add(clean_subdomain(sub))
                        if match := re.search(r'<a.*?href="(.*?)">Next Page', text): next_url = base + match.group(1)
                        else: next_url = None
                    await asyncio.sleep(1)
        except Exception: pass
        return f
class DNSdumpsterFree(Source):
    def __init__(self): super().__init__("dnsdumpster_free")
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        u, f = "https://dnsdumpster.com/", set()
        try:
            async with s.get(u, timeout=aiohttp.ClientTimeout(total=3)) as r_get:
                if r_get.status != 200: return f
                if not (m := re.search(r'<input type="hidden" name="csrfmiddlewaretoken" value="(.*?)">', await r_get.text())): return f
                csrf, cookies = m.group(1), {'csrftoken': m.group(1)}
                data = {'csrfmiddlewaretoken': csrf, 'targetip': d, 'user': 'free'}
                async with s.post(u, data=data, headers={'Referer': u}, cookies=cookies, timeout=aiohttp.ClientTimeout(total=3)) as r_post:
                    if r_post.status != 200: return f
                    regex = r'(?:<td class="col-md-4">|<td class="col-md-3">)([^<]*\.' + re.escape(d) + ')<br>'
                    for link in re.findall(regex, await r_post.text()): f.add(clean_subdomain(link))
        except Exception: pass
        return f
class GauWayback(Source):
    def __init__(self): super().__init__("gau_wayback")
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        f, page = set(), 0
        while True:
            try:
                u = f"https://web.archive.org/cdx/search/cdx?url=*.{d}/*&output=json&collapse=urlkey&fl=original&pageSize=500&page={page}"
                async with s.get(u, timeout=aiohttp.ClientTimeout(total=3)) as r:
                    if r.status != 200: break
                    data = await r.json(content_type=None)
                    if len(data) <= 1: break
                    f.update(clean_subdomain(h) for item in data[1:] if item and isinstance(item, list) and item[0] and (h := urlparse.urlparse(item[0]).netloc))
                    if len(data) < 501: break
                    page += 1
            except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): break
        return f
class GauCommoncrawl(Source):
    def __init__(self): super().__init__("gau_commoncrawl")
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        f, api = set(), None
        try:
            async with s.get("http://index.commoncrawl.org/collinfo.json", timeout=aiohttp.ClientTimeout(total=3)) as r_api:
                if r_api.status == 200 and (apis := await r_api.json()) and isinstance(apis, list) and 'cdx-api' in apis[0]: api = apis[0]['cdx-api']
        except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): return f
        if not api: return f
        page = 0
        while True:
            try:
                async with s.get(f"{api}?url=*.{d}/*&output=json&page={page}", timeout=aiohttp.ClientTimeout(total=3)) as r:
                    if r.status != 200: break
                    lines = (await r.text()).strip().split('\n')
                    if not lines or (len(lines) == 1 and not lines[0]): break
                    found = False
                    for line in lines:
                        try:
                            if url := json.loads(line).get('url'):
                                if h := urlparse.urlparse(url).netloc: f.add(clean_subdomain(h)); found = True
                        except (json.JSONDecodeError, UnicodeDecodeError): continue
                    if not found: break
                    page += 1; await asyncio.sleep(0.5)
            except (aiohttp.ClientError, asyncio.TimeoutError): break
        return f
class GauAlienvaultOtx(Source):
    def __init__(self): super().__init__("gau_alienvault_otx")
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        f, page = set(), 1
        while True:
            try:
                u = f"https://otx.alienvault.com/api/v1/indicators/domain/{d}/url_list?limit=100&page={page}"
                async with s.get(u, timeout=aiohttp.ClientTimeout(total=3)) as r:
                    if r.status != 200: break
                    data = await r.json()
                    f.update(clean_subdomain(h) for e in data.get('url_list', []) if (url := e.get('url')) and (h := urlparse.urlparse(url).netloc) and h.endswith(f".{d}"))
                    if not data.get('has_next', False): break
                    page += 1
            except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): break
        return f
class Crtsh(Source):
    def __init__(self): super().__init__("crtsh")
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        u, f = f"https://crt.sh/?q=%.{d}&output=json", set()
        try:
            async with s.get(u, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status==200:
                    f.update(clean_subdomain(sub) for e in await r.json(content_type=None) for sub in e.get('name_value', '').split('\n') if sub and sub.endswith(f".{d}"))
        except (json.JSONDecodeError, aiohttp.ClientError, aiohttp.ContentTypeError, asyncio.TimeoutError): pass
        return f
class CertspotterFree(Source):
    def __init__(self): super().__init__("certspotter_free")
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        u, f = f"https://certspotter.com/api/v0/certs?domain={d}", set()
        try:
            async with s.get(u, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200:
                    f.update(clean_subdomain(name) for w in await r.json(content_type=None) for name in w.get('dns_names', []))
        except (json.JSONDecodeError, aiohttp.ClientError, aiohttp.ContentTypeError, asyncio.TimeoutError): pass
        return f
class BufferoverFree(Source):
    def __init__(self): super().__init__("bufferover_free")
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        u, f = f"https://dns.bufferover.run/dns?q=.{d}", set()
        try:
            async with s.get(u, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200:
                    f.update(clean_subdomain(p[1]) for r_str in (await r.json(content_type=None)).get('FDNS_A', []) if len(p := r_str.split(',', 1)) == 2)
        except (json.JSONDecodeError, aiohttp.ClientError, aiohttp.ContentTypeError, asyncio.TimeoutError): pass
        return f
class Alienvault(Source):
    def __init__(self): super().__init__("alienvault")
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        u, f = f"https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns", set()
        try:
            async with s.get(u, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200:
                    f.update(clean_subdomain(rec['hostname']) for rec in (await r.json()).get('passive_dns', []) if rec.get('hostname'))
        except (json.JSONDecodeError, aiohttp.ClientError, asyncio.TimeoutError): pass
        return f
class Anubis(Source):
    def __init__(self): super().__init__("anubis")
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        u, f = f"https://jonlu.ca/anubis/subdomains/{d}", set()
        try:
            async with s.get(u, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200: f.update(clean_subdomain(sub) for sub in await r.json())
        except (json.JSONDecodeError, aiohttp.ClientError, asyncio.TimeoutError): pass
        return f
class Commoncrawl(Source):
    def __init__(self): super().__init__("commoncrawl")
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        u, f = f"http://index.commoncrawl.org/CC-MAIN-2023-50-index?url=*.{d}&output=json", set()
        regex = re.compile(rf"([a-zA-Z0-9.\-]+\.{re.escape(d)})")
        try:
            async with s.get(u, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200:
                    async for line in r.content:
                        try:
                            if url := json.loads(line).get('url'): f.update(clean_subdomain(m) for m in regex.findall(url))
                        except (json.JSONDecodeError, UnicodeDecodeError): continue
        except (aiohttp.ClientError, asyncio.TimeoutError): pass
        return f
class Digitorus(Source):
    def __init__(self): super().__init__("digitorus")
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        u, f = f"https://certificatedetails.com/{d}", set()
        regex = re.compile(rf'([a-zA-Z0-9.\-]+\.{re.escape(d)})')
        try:
            async with s.get(u, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status in [200, 404]: f.update(clean_subdomain(m) for m in regex.findall(await r.text()))
        except (aiohttp.ClientError, asyncio.TimeoutError): pass
        return f
class Hackertarget(Source):
    def __init__(self): super().__init__("hackertarget")
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        u, f = f"https://api.hackertarget.com/hostsearch/?q={d}", set()
        try:
            async with s.get(u, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200:
                    f.update(clean_subdomain(line.split(',')[0]) for line in (await r.text()).split('\n') if line)
        except (aiohttp.ClientError, asyncio.TimeoutError): pass
        return f
class Hudsonrock(Source):
    def __init__(self): super().__init__("hudsonrock")
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        u, f = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain?domain={d}", set()
        regex = re.compile(rf"([a-zA-Z0-9.\-]+\.{re.escape(d)})")
        try:
            async with s.get(u, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200:
                    ds = (await r.json()).get('data', {})
                    urls = [e.get('url') for e in ds.get('employees_urls',[]) if e.get('url')]
                    urls.extend(c.get('url') for c in ds.get('clients_urls',[]) if c.get('url'))
                    f.update(clean_subdomain(m) for url in urls for m in regex.findall(url))
        except (json.JSONDecodeError, aiohttp.ClientError, asyncio.TimeoutError): pass
        return f
class Rapiddns(Source):
    def __init__(self): super().__init__("rapiddns")
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        u, f = f"https://rapiddns.io/subdomain/{d}?full=1", set()
        regex = re.compile(rf'([a-zA-Z0-9.\-]+\.{re.escape(d)})')
        try:
            async with s.get(u, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200: f.update(clean_subdomain(m) for m in regex.findall(await r.text()))
        except (aiohttp.ClientError, asyncio.TimeoutError): pass
        return f
class Sitedossier(Source):
    def __init__(self): super().__init__("sitedossier")
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        u, f = f"http://www.sitedossier.com/parentdomain/{d}", set()
        regex = re.compile(rf'([a-zA-Z0-9.\-]+\.{re.escape(d)})')
        try:
            async with s.get(u, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200: f.update(clean_subdomain(m) for m in regex.findall(await r.text()))
        except (aiohttp.ClientError, asyncio.TimeoutError): pass
        return f
class Threatcrowd(Source):
    def __init__(self): super().__init__("threatcrowd")
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        u, f = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={d}", set()
        try:
            async with s.get(u, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200: f.update(clean_subdomain(sub) for sub in (await r.json(content_type=None)).get('subdomains', []))
        except (json.JSONDecodeError, aiohttp.ClientError, aiohttp.ContentTypeError, asyncio.TimeoutError): pass
        return f
class Waybackarchive(Source):
    def __init__(self): super().__init__("waybackarchive")
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        u, f = f"http://web.archive.org/cdx/search/cdx?url=*.{d}/*&output=txt&fl=original&collapse=urlkey", set()
        regex = re.compile(rf"([a-zA-Z0-9.\-]+\.{re.escape(d)})")
        try:
            async with s.get(u, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200: f.update(clean_subdomain(m) for m in regex.findall(await r.text()))
        except (aiohttp.ClientError, asyncio.TimeoutError): pass
        return f
class Threatminer(Source):
    def __init__(self): super().__init__("threatminer")
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        u, f = f"https://api.threatminer.org/v2/domain.php?q={d}&rt=5", set()
        try:
            async with s.get(u, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200 and (data := await r.json(content_type=None)).get('status_code') == '200':
                    f.update(clean_subdomain(sub) for sub in data.get('results', []))
        except (json.JSONDecodeError, aiohttp.ClientError, aiohttp.ContentTypeError, asyncio.TimeoutError): pass
        return f
class Sublist3r(Source):
    def __init__(self): super().__init__("sublist3r")
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        u, f = f"https://api.sublist3r.com/search.php?domain={d}", set()
        try:
            async with s.get(u, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200 and (data := await r.json(content_type=None)):
                    f.update(clean_subdomain(sub) for sub in data)
        except (json.JSONDecodeError, aiohttp.ClientError, aiohttp.ContentTypeError, asyncio.TimeoutError): pass
        return f
class Ctsearch(Source):
    def __init__(self): super().__init__("ctsearch")
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        u, f = f"https://ui.ctsearch.entrust.com/api/v1/search?field=subjectCN&query={d}&size=5000", set()
        try:
            async with s.get(u, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200:
                    f.update(clean_subdomain(item['subjectCN']) for item in (await r.json(content_type=None)).get('items', []) if item.get('subjectCN'))
        except (json.JSONDecodeError, aiohttp.ClientError, aiohttp.ContentTypeError, asyncio.TimeoutError): pass
        return f
class Urlscan(Source):
    def __init__(self): super().__init__("urlscan", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        f, search_after, headers = set(), "", {}
        if key := self.get_random_key(): headers['API-Key'] = key
        while True:
            try:
                u = f"https://urlscan.io/api/v1/search/?q=domain:{d}&size=100"
                if search_after: u += f"&search_after={search_after}"
                async with s.get(u, headers=headers, timeout=aiohttp.ClientTimeout(total=3)) as r:
                    if r.status in [429, 400]: break
                    data = await r.json(content_type=None)
                    results = data.get('results', [])
                    if not results: break
                    f.update(clean_subdomain(h) for res in results if (p_url := res.get('page',{}).get('url')) and (h := urlparse.urlparse(p_url).netloc) and h.endswith(f".{d}"))
                    if data.get('has_more') and results and (last_sort := results[-1].get('sort')) and len(last_sort) == 2:
                        search_after = f"{last_sort[0]},{last_sort[1]}"
                    else: break
            except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): break
        return f
class Github(Source):
    def __init__(self): super().__init__("github", True)
    def _get_raw_url(self, html_url: str) -> Optional[str]:
        if "github.com" not in html_url or "/blob/" not in html_url: return None
        return html_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
    async def _process_item(self, item: dict, domain: str, session: aiohttp.ClientSession, regex: re.Pattern) -> Set[str]:
        found = set()
        if not (html_url := item.get('html_url')) or not (raw_url := self._get_raw_url(html_url)): return found
        try:
            async with session.get(raw_url, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200: found.update(clean_subdomain(m) for m in regex.findall(await r.text()))
        except Exception: pass
        return found
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()): return set()
        all_found, regex = set(), re.compile(rf"([a-zA-Z0-9.\-]+\.{re.escape(d)})")
        headers = {'Authorization': f'token {key}', 'Accept': 'application/vnd.github.v3+json'}
        for page in range(1, 11):
            u = f'https://api.github.com/search/code?q="{d}"&per_page=100&page={page}'
            try:
                async with s.get(u, headers=headers, timeout=aiohttp.ClientTimeout(total=3)) as r:
                    if r.status != 200: break
                    if not (items := (await r.json(content_type=None)).get('items', [])): break
                    tasks = [self._process_item(item, d, s, regex) for item in items]
                    for sub_set in await asyncio.gather(*tasks, return_exceptions=True):
                        if isinstance(sub_set, set): all_found.update(sub_set)
            except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): break
        return all_found
class Spyse(Source):
    def __init__(self): super().__init__("spyse", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()): return set()
        f = set()
        try:
            async with s.get(f"https://api.spyse.com/v1/subdomains-aggregate?api_token={key}&domain={d}", timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200:
                    cidrs = (await r.json()).get('cidr', {})
                    f.update(clean_subdomain(dom) for c_type in ['Cidr16', 'Cidr24'] for res in cidrs.get(c_type, {}).get('Results', []) for dom in res.get('Data', {}).get('Domains', []))
        except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): pass
        page = 1
        while True:
            try:
                async with s.get(f"https://api.spyse.com/v1/subdomains?api_token={key}&domain={d}&page={page}", timeout=aiohttp.ClientTimeout(total=3)) as r:
                    if r.status != 200: break
                    if not (recs := (await r.json()).get('records', [])): break
                    f.update(clean_subdomain(rec['domain']) for rec in recs if rec.get('domain'))
                    page += 1
            except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): break
        return f
class Bevigil(Source):
    def __init__(self): super().__init__("bevigil", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()): return set()
        try:
            async with s.get(f"https://osint.bevigil.com/api/{d}/subdomains/", headers={'X-Access-Token': key}, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200: return {clean_subdomain(sub) for sub in (await r.json()).get('subdomains', [])}
        except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): pass
        return set()
class Binaryedge(Source):
    def __init__(self): super().__init__("binaryedge", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()): return set()
        f, page = set(), 1
        while True:
            try:
                async with s.get(f"https://api.binaryedge.io/v2/query/domains/subdomain/{d}?page={page}", headers={'X-Key': key}, timeout=aiohttp.ClientTimeout(total=3)) as r:
                    if r.status != 200: break
                    events = (await r.json()).get('events', [])
                    if not events: break
                    f.update(clean_subdomain(e) for e in events)
                    if len(events) < 100: break
                    page += 1
            except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): break
        return f
class Bufferover(Source):
    def __init__(self): super().__init__("bufferover", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()): return set()
        try:
            async with s.get(f"https://tls.bufferover.run/dns?q=.{d}", headers={'x-api-key': key}, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    all_doms = (data.get('FDNS_A', []) or []) + (data.get('RDNS', []) or [])
                    return {clean_subdomain(sub) for item in all_doms if item for sub in item.split(',')}
        except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): pass
        return set()
class Builtwith(Source):
    def __init__(self): super().__init__("builtwith", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()): return set()
        try:
            async with s.get(f"https://api.builtwith.com/v21/api.json?KEY={key}&LOOKUP={d}", timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200:
                    return {clean_subdomain(f"{p['SubDomain']}.{p['Domain']}") for res in (await r.json()).get('Results', []) for p in res.get('Result', {}).get('Paths', []) if p.get('SubDomain') and p.get('Domain') and d in p.get('Domain')}
        except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): pass
        return set()
class C99(Source):
    def __init__(self): super().__init__("c99", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()): return set()
        try:
            async with s.get(f"https://api.c99.nl/subdomainfinder?key={key}&domain={d}&json", timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200 and (data := await r.json()).get('success'):
                    return {clean_subdomain(sub['subdomain']) for sub in data.get('subdomains', []) if sub.get('subdomain')}
        except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): pass
        return set()
class Censys(Source):
    def __init__(self): super().__init__("censys", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()) or ':' not in key: return set()
        api_id, secret = key.split(':', 1)
        f, cursor = set(), ""
        while True:
            u = f"https://search.censys.io/api/v2/certificates/search?q={d}&per_page=100"
            if cursor: u += f"&cursor={cursor}"
            try:
                async with s.get(u, auth=aiohttp.BasicAuth(api_id, secret), timeout=aiohttp.ClientTimeout(total=3)) as r:
                    if r.status != 200: break
                    data = await r.json()
                    f.update(clean_subdomain(name) for hit in data.get('result', {}).get('hits', []) for name in hit.get('names', []))
                    if not (cursor := data.get('result', {}).get('links', {}).get('next')): break
            except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): break
        return f
class Certspotter(Source):
    def __init__(self): super().__init__("certspotter", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()): return set()
        try:
            async with s.get(f"https://api.certspotter.com/v1/issuances?domain={d}&include_subdomains=true&expand=dns_names", headers={'Authorization': f'Bearer {key}'}, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200:
                    return {clean_subdomain(name) for item in await r.json() for name in item.get('dns_names', [])}
        except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): pass
        return set()
class Chaos(Source):
    def __init__(self): super().__init__("chaos", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()): return set()
        try:
            async with s.get(f"https://dns.projectdiscovery.io/dns/{d}/subdomains", headers={'Authorization': key}, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200:
                    return {f"{sub}.{d}" for sub in (await r.json()).get('subdomains', [])}
        except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): pass
        return set()
class ChaosPublicRecon(Source):
    def __init__(self): super().__init__("chaospublicrecon", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()): return set()
        f = set()
        try:
            async with s.get(f"https://dns.projectdiscovery.io/dns/{d}/public-recon-data", headers={'Authorization': key}, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200:
                    async for line in r.content:
                        if not line: continue
                        try:
                            data = json.loads(line)
                            if (sub := data.get('subdomain')) and (dom := data.get('domain')): f.add(clean_subdomain(f"{sub}.{dom}"))
                        except (json.JSONDecodeError, UnicodeDecodeError): continue
        except (aiohttp.ClientError, asyncio.TimeoutError): pass
        return f
class Chinaz(Source):
    def __init__(self): super().__init__("chinaz", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()): return set()
        try:
            async with s.get(f"https://apidatav2.chinaz.com/single/alexa?key={key}&domain={d}", timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200:
                    return {clean_subdomain(item['DataUrl']) for item in (await r.json()).get('Result', {}).get('ContributingSubdomainList', []) if item.get('DataUrl')}
        except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): pass
        return set()
class Dnsdumpster(Source):
    def __init__(self): super().__init__("dnsdumpster", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()): return set()
        try:
            async with s.get(f"https://api.dnsdumpster.com/domain/{d}", headers={'X-API-Key': key}, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200:
                    data = await r.json()
                    return {clean_subdomain(rec['host']) for sec in ['a', 'ns'] for rec in data.get(sec, []) if rec.get('host')}
        except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): pass
        return set()
class Dnsrepo(Source):
    def __init__(self): super().__init__("dnsrepo", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()) or ':' not in key: return set()
        token, api_key = key.split(':', 1)
        try:
            async with s.get(f"https://dnsarchive.net/api/?apikey={api_key}&search={d}", headers={'X-API-Access': token}, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200:
                    return {clean_subdomain(item['domain']) for item in await r.json() if item.get('domain')}
        except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): pass
        return set()
class Facebook(Source):
    def __init__(self): super().__init__("facebook", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()) or ':' not in key: return set()
        app_id, secret = key.split(':', 1)
        token = None
        try:
            async with s.get(f"https://graph.facebook.com/oauth/access_token?client_id={app_id}&client_secret={secret}&grant_type=client_credentials", timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200: token = (await r.json()).get('access_token')
        except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): return set()
        if not token: return set()
        f, next_page = set(), f"https://graph.facebook.com/certificates?fields=domains&access_token={token}&query={d}&limit=1000"
        while next_page:
            try:
                async with s.get(next_page, timeout=aiohttp.ClientTimeout(total=3)) as r:
                    if r.status != 200: break
                    data = await r.json()
                    f.update(clean_subdomain(sub) for item in data.get('data', []) for sub in item.get('domains', []))
                    next_page = data.get('paging', {}).get('next')
            except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): break
        return f
class Fofa(Source):
    def __init__(self): super().__init__("fofa", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()) or ':' not in key: return set()
        email, api_key = key.split(':', 1)
        query = base64.b64encode(f'domain="{d}"'.encode()).decode()
        u = f"https://fofa.info/api/v1/search/all?email={email}&key={api_key}&qbase64={query}&size=10000"
        try:
            async with s.get(u, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200 and not (data := await r.json()).get('error'):
                    return {clean_subdomain(res if not isinstance(res, list) else res[0]) for res in data.get('results', [])}
        except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): pass
        return set()
class Fullhunt(Source):
    def __init__(self): super().__init__("fullhunt", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()): return set()
        try:
            async with s.get(f"https://fullhunt.io/api/v1/domain/{d}/subdomains", headers={'X-API-KEY': key}, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200:
                    return {clean_subdomain(h) for h in (await r.json()).get('hosts', [])}
        except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): pass
        return set()
class Hunter(Source):
    def __init__(self): super().__init__("hunter", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()): return set()
        f, page = set(), 1
        query = base64.urlsafe_b64encode(f'domain="{d}"'.encode()).decode()
        while True:
            u = f"https://hunter.qianxin.com/openApi/search?api-key={key}&search={query}&page={page}&page_size=100&is_web=3"
            try:
                async with s.get(u, timeout=aiohttp.ClientTimeout(total=3)) as r:
                    if r.status != 200: break
                    data = await r.json()
                    arr = data.get('data', {}).get('arr', [])
                    if not arr: break
                    f.update(clean_subdomain(item['domain']) for item in arr if item.get('domain'))
                    if page * 100 >= data.get('data', {}).get('total', 0): break
                    page += 1
            except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): break
        return f
class Intelx(Source):
    def __init__(self): super().__init__("intelx", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()) or ':' not in key: return set()
        host, api_key = key.split(':', 1)
        search_id = None
        data = {'term': d, 'maxresults': 100000, 'media': 0, 'target': 1, 'timeout': 20}
        try:
            async with s.post(f"https://{host}/phonebook/search?k={api_key}", json=data, headers={'Content-Type': 'application/json'}, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200: search_id = (await r.json()).get('id')
        except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): return set()
        if not search_id: return set()
        f = set()
        for _ in range(5):
            try:
                async with s.get(f"https://{host}/phonebook/search/result?k={api_key}&id={search_id}&limit=10000", timeout=aiohttp.ClientTimeout(total=3)) as r:
                    if r.status == 200:
                        res = await r.json()
                        f.update(clean_subdomain(sel['selectorvalue']) for sel in res.get('selectors', []) if sel.get('selectorvalue'))
                        if res.get('status') in [1, 2]: break
            except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): break
            await asyncio.sleep(2)
        return f
class Leakix(Source):
    def __init__(self): super().__init__("leakix", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        headers = {'accept': 'application/json'}
        if key := self.get_random_key(): headers['api-key'] = key
        try:
            async with s.get(f"https://leakix.net/api/subdomains/{d}", headers=headers, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200:
                    return {clean_subdomain(item['subdomain']) for item in await r.json() if item.get('subdomain')}
        except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): pass
        return set()
class Netlas(Source):
    def __init__(self): super().__init__("netlas", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()): return set()
        q = f'domain:*.{d}'
        h = {'X-API-Key': key, 'Content-Type': 'application/json'}
        try:
            async with s.get(f"https://app.netlas.io/api/domains/?q={q}&source_type=include&start=0&count=1000", headers=h, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200:
                    return {clean_subdomain(item['data']['domain']) for item in await r.json() if item.get('data', {}).get('domain')}
        except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): pass
        return set()
class Quake(Source):
    def __init__(self): super().__init__("quake", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()): return set()
        data = {'query': f'domain: "{d}"', 'start': 0, 'size': 500}
        headers = {'X-QuakeToken': key, 'Content-Type': 'application/json'}
        try:
            async with s.post("https://quake.360.net/api/v3/search/quake_service", json=data, headers=headers, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200 and (res := await r.json()).get('code') == 0:
                    return {clean_subdomain(h) for i in res.get('data', []) if (h := i.get('service', {}).get('http', {}).get('host'))}
        except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): pass
        return set()
class Redhuntlabs(Source):
    def __init__(self): super().__init__("redhuntlabs", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()) or ':' not in key: return set()
        base, _, api = key.partition(':')
        base = "https://recon.redhuntlabs.com/api/v1/domains" if not base else base
        try:
            async with s.get(f"{base}?domain={d}", headers={'X-BLOBR-KEY': api}, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200:
                    return {clean_subdomain(sub) for sub in (await r.json()).get('subdomains', [])}
        except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): pass
        return set()
class Robtex(Source):
    def __init__(self): super().__init__("robtex", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()): return set()
        f = set()
        try:
            async with s.get(f"https://proapi.robtex.com/pdns/forward/{d}?key={key}", timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200:
                    for line in (await r.text()).strip().split('\n'):
                        try:
                            if rrname := json.loads(line).get('rrname'): f.add(clean_subdomain(rrname))
                        except json.JSONDecodeError: continue
        except (aiohttp.ClientError, asyncio.TimeoutError): pass
        return f
class Securitytrails(Source):
    def __init__(self): super().__init__("securitytrails", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()): return set()
        try:
            async with s.get(f"https://api.securitytrails.com/v1/domain/{d}/subdomains", headers={'APIKEY': key}, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200:
                    return {f"{sub}.{d}" for sub in (await r.json()).get('subdomains', [])}
        except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): pass
        return set()
class Shodan(Source):
    def __init__(self): super().__init__("shodan", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()): return set()
        f, page = set(), 1
        while True:
            try:
                async with s.get(f"https://api.shodan.io/dns/domain/{d}?key={key}&page={page}", timeout=aiohttp.ClientTimeout(total=3)) as r:
                    if r.status != 200: break
                    data = await r.json()
                    f.update(f"{sub}.{d}" for sub in data.get('subdomains', []))
                    if not data.get('more', False): break
                    page += 1
            except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): break
        return f
class Threatbook(Source):
    def __init__(self): super().__init__("threatbook", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()): return set()
        try:
            async with s.get(f"https://api.threatbook.cn/v3/domain/sub_domains?apikey={key}&resource={d}", timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200 and (data := await r.json()).get('response_code') == 0:
                    return {clean_subdomain(sub) for sub in data.get('data', {}).get('sub_domains', {}).get('data', [])}
        except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): pass
        return set()
class Virustotal(Source):
    def __init__(self): super().__init__("virustotal", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()): return set()
        f, cursor = set(), ""
        while True:
            u = f"https://www.virustotal.com/api/v3/domains/{d}/subdomains?limit=40"
            if cursor: u += f"&cursor={cursor}"
            try:
                async with s.get(u, headers={'x-apikey': key}, timeout=aiohttp.ClientTimeout(total=3)) as r:
                    if r.status != 200: break
                    data = await r.json()
                    f.update(clean_subdomain(item['id']) for item in data.get('data', []) if item.get('id'))
                    if not (cursor := data.get('meta', {}).get('cursor')): break
            except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): break
        return f
class Whoisxmlapi(Source):
    def __init__(self): super().__init__("whoisxmlapi", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()): return set()
        try:
            async with s.get(f"https://subdomains.whoisxmlapi.com/api/v1?apiKey={key}&domainName={d}", timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200:
                    return {clean_subdomain(rec['domain']) for rec in (await r.json()).get('result', {}).get('records', []) if rec.get('domain')}
        except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): pass
        return set()
class Zoomeyeapi(Source):
    def __init__(self): super().__init__("zoomeyeapi", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()): return set()
        host, api_key = key.split(':', 1) if ':' in key else ("api.zoomeye.org", key)
        f, page = set(), 1
        while True:
            u = f"https://{host}/domain/search?q={d}&type=1&s=1000&page={page}"
            try:
                async with s.get(u, headers={'API-KEY': api_key}, timeout=aiohttp.ClientTimeout(total=3)) as r:
                    if r.status != 200: break
                    data = await r.json()
                    if not (items := data.get('list', [])): break
                    f.update(clean_subdomain(item['name']) for item in items if item.get('name'))
                    if page * 1000 >= data.get('total', 0): break
                    page += 1
            except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): break
        return f
class Digitalyama(Source):
    def __init__(self): super().__init__("digitalyama", True)
    async def find(self, d: str, s: aiohttp.ClientSession) -> Set[str]:
        if not (key := self.get_random_key()): return set()
        try:
            async with s.get(f"https://api.digitalyama.com/subdomain_finder?domain={d}", headers={'x-api-key': key}, timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200:
                    return {clean_subdomain(sub) for sub in (await r.json()).get('subdomains', [])}
        except (aiohttp.ClientError, json.JSONDecodeError, asyncio.TimeoutError): pass
        return set()

# --- Scanner Class ---
class Scanner:
    """Runs scans and updates the central state."""
    # MODIFIED: Added 'output_file' parameter to decouple file writing from the UI
    def __init__(self, sources: List[Source], ui_manager: Optional[UIManager], scan_state: Dict, resume_path: Optional[str], output_file: Optional[TextIO] = None):
        self.sources = sources
        self.ui = ui_manager
        self.scan_state = scan_state
        self.resume_path = resume_path
        self.timeout = aiohttp.ClientTimeout(total=40)
        self.output_file = output_file  # ADDED: Store the output file handle

    # MODIFIED: This method now writes to the file as soon as new subdomains are found.
    async def run_scan_for_domains(self, domains_to_scan: List[str], global_found: Set[str]) -> Set[str]:
        total_in_phase = len(domains_to_scan)
        if self.ui:
            await self.ui.update_state_and_notify({'total_domains_in_phase': total_in_phase})
        
        for i, domain in enumerate(domains_to_scan):
            if self.ui:
                await self.ui.update_state_and_notify({
                    'current_domain': domain, 'completed_domains': i,
                    'completed_sources': 0,
                    'source_status': {s.name: "Pending..." for s in self.sources}
                }, force_notify=True)

            async with aiohttp.ClientSession(timeout=self.timeout, connector=aiohttp.TCPConnector(ssl=False)) as session:
                tasks = [self.run_source(s, domain, session) for s in self.sources]
                for res_set in await asyncio.gather(*tasks):
                    if res_set:
                        newly_found = res_set - global_found
                        if newly_found:
                            global_found.update(newly_found)
                            
                            # ADDED: Real-time writing logic.
                            # This writes to the file immediately, even in silent mode.
                            if self.output_file:
                                self.output_file.write('\n'.join(sorted(list(newly_found))) + '\n')
                                self.output_file.flush()

                            if self.ui:
                                # The original code's writing logic was here, inside the UI check.
                                # It has been moved out to support silent mode correctly.
                                await self.ui.update_state_and_notify({'sub_count': len(global_found)})
            
            self.scan_state['completed_domains_list'].append(domain)
            self.scan_state['found_subdomains'] = sorted(list(global_found))
            save_state_to_yaml(self.scan_state, self.resume_path)

        if self.ui: self.ui.finish()
        return global_found

    async def run_source(self, source: Source, domain: str, session: aiohttp.ClientSession) -> Optional[Set[str]]:
        if self.ui:
            statuses = self.scan_state.get('source_status', {}).copy()
            statuses[source.name] = "Running..."
            await self.ui.update_state_and_notify({'source_status': statuses})
        
        found, msg = set(), "No results."
        try:
            found = await source.find(domain, session)
            if found: msg = f"Found {len(found)}."
        except asyncio.TimeoutError: msg = "Failed (Timeout)"
        except Exception as e: logging.error(f"Source {source.name} on {domain} failed: {e}"); msg = "Failed (Error)"
        
        if self.ui:
            statuses = self.scan_state.get('source_status', {}).copy()
            statuses[source.name] = msg
            completed = self.scan_state.get('completed_sources', 0) + 1
            await self.ui.update_state_and_notify({'source_status': statuses, 'completed_sources': completed})
        return found

# --- Helper Functions for Resume ---
def save_state_to_yaml(state: Dict, filepath: str):
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            yaml.dump(state, f, default_flow_style=False, sort_keys=False)
    except IOError as e:
        logging.error(f"Could not save resume state to {filepath}: {e}")
def load_state_from_yaml(filepath: str) -> Optional[Dict]:
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except (IOError, yaml.YAMLError) as e:
        logging.error(f"Could not load resume state from {filepath}: {e}")
        return None

# --- Helper Functions ---
def write_set_to_file(filepath: str, data: Set[str]):
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(list(data))) + '\n')
def read_file_to_set(filepath: str) -> Set[str]:
    if not os.path.exists(filepath): return set()
    with open(filepath, 'r', encoding='utf-8') as f: return {line.strip() for line in f if line.strip()}
def list_all_sources(all_source_classes):
    keyless = sorted([sc().name for sc in all_source_classes if not sc().needs_key])
    key_based = sorted([sc().name for sc in all_source_classes if sc().needs_key])
    print("--- Available Subdomain Sources ---")
    print(f"\n[+] Key-less ({len(keyless)}): " + ", ".join(keyless))
    print(f"\n[+] Key-based ({len(key_based)}): " + ", ".join(key_based))
def list_endpoint_sources():
    external, internal = ["gauplus", "waybackurls", "hakrawler"], ["otx_api", "urlscan_api", "js_grabber"]
    print("--- Available Endpoint & JS Sources ---\n[+] Internal: " + ", ".join(internal) + "\n[+] External: " + ", ".join(external))

# --- Main Logic ---
async def main():
    if '-s' not in sys.argv and '--silent' not in sys.argv:
        print_banner()

    all_source_classes = [
        OpenSSL_SAN, Google, Yahoo, Bing, Ask, Baidu, Netcraft, DNSdumpsterFree, GauWayback, GauCommoncrawl, 
        GauAlienvaultOtx, Crtsh, CertspotterFree, BufferoverFree, Alienvault, Anubis, Commoncrawl, Digitorus, 
        Hackertarget, Hudsonrock, Rapiddns, Sitedossier, Threatcrowd, Waybackarchive, Threatminer, Sublist3r, 
        Ctsearch, Urlscan, Github, Spyse, Bevigil, Binaryedge, Bufferover, Builtwith, C99, Censys, 
        Certspotter, Chaos, ChaosPublicRecon, Chinaz, Dnsdumpster, Dnsrepo, Facebook, Fofa, Fullhunt, 
        Hunter, Intelx, Leakix, Netlas, Quake, Redhuntlabs, Robtex, Securitytrails, Shodan, Threatbook, 
        Virustotal, Whoisxmlapi, Zoomeyeapi, Digitalyama
    ]

    if '--sources' in sys.argv:
        list_all_sources(all_source_classes)
        sys.exit(0)
    if '--endpoint-sources' in sys.argv:
        list_endpoint_sources()
        sys.exit(0)
    
    parser = argparse.ArgumentParser(description="Interactive multi-source subdomain scanner.", add_help=False, formatter_class=argparse.RawTextHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("domain", nargs='?', default=None, help="Single domain to scan.")
    group.add_argument("-l", "--list", help="File of domains to scan.")
    group.add_argument("--resume", help="Resume a previous scan from a YAML state file.")
    
    parser.add_argument("-h", "--help", action="help", default=argparse.SUPPRESS, help="Show this help message and exit.")
    parser.add_argument("-o", "--output", help="File to save results.")
    parser.add_argument("-s", "--silent", action="store_true", help="Silent mode (no console UI or banner).")
    parser.add_argument("--sources", action="store_true", help="List subdomain sources and exit.")
    parser.add_argument("--recursive", action="store_true", help="Enable recursive scanning.")
    parser.add_argument("--endpoint", action="store_true", help="Grab known URLs and JS files after subdomain scan.")
    parser.add_argument("--endpoint-sources", action="store_true", help="List endpoint sources and exit.")
    parser.add_argument("--keep-resume", action="store_true", help="Do not delete the resume file on successful completion.")
    
    args = parser.parse_args()

    logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')
    api_keys = {k.lower(): v for k, v in API_KEYS.items()}
    
    active_sources = []
    for sc_class in all_source_classes:
        sc_instance = sc_class()
        if not sc_instance.needs_key:
            active_sources.append(sc_instance)
        elif sc_instance.name in api_keys and api_keys[sc_instance.name]:
            sc_instance.add_keys(api_keys[sc_instance.name])
            active_sources.append(sc_instance)
            
    if not args.silent: print(f"[*] Active sources: {len(active_sources)} ({len([s for s in active_sources if s.needs_key])} key-based).")

    scan_state = {}
    resume_file_path = None
    initial_domains = set()
    final_subs = set()

    if args.resume:
        print(f"[*] Attempting to resume scan from: {args.resume}")
        scan_state = load_state_from_yaml(args.resume)
        if not scan_state: parser.error(f"Failed to load or parse resume file: {args.resume}")
        saved_args = SimpleNamespace(**scan_state.get('args', {}))
        # Ensure resume keeps original output file settings
        args.output = saved_args.output
        if 'recursive' in saved_args: args.recursive = saved_args.recursive
        if 'endpoint' in saved_args: args.endpoint = saved_args.endpoint
        
        print("[+] Resumed Configuration:")
        print(f"    - Recursive: {args.recursive}\n    - Endpoint Scan: {args.endpoint}\n    - Output File: {args.output}")
        initial_domains = set(scan_state.get('total_domains_list', []))
        final_subs = set(scan_state.get('found_subdomains', []))
        resume_file_path = args.resume
    else:
        if args.list:
            try: initial_domains = read_file_to_set(args.list)
            except FileNotFoundError: parser.error(f"File not found: {args.list}")
            if not initial_domains: parser.error(f"File '{args.list}' is empty.")
        elif args.domain:
            initial_domains.add(args.domain)
        else:
            parser.error("A domain (`domain`), list file (`-l`), or resume file (`--resume`) is required.")
        initial_domains = {d.lstrip('*.') for d in initial_domains}
        date_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        resume_file_path = f"resume_{date_str}.yaml"
        print(f"[*] Scan state will be saved to: {resume_file_path}")
        scan_state = {'args': vars(args), 'total_domains_list': sorted(list(initial_domains)), 'completed_domains_list': [], 'found_subdomains': [], 'endpoint_scan_started': False}
        save_state_to_yaml(scan_state, resume_file_path)

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as tg_session:
        source_names = [s.name for s in active_sources]
        scan_state.update({'mode': 'Recursive' if args.recursive else 'Normal', 'status': 'Started', 'sub_count': len(final_subs), 'url_count': 0, 'js_count': 0, 'endpoint_scan_active': False, 'endpoint_status': 'Pending', 'num_sources': len(active_sources), 'total_domains_list': sorted(list(initial_domains))})
        telegram_notifier = TelegramNotifier(TELEGRAM_CONFIG, tg_session)
        listener_task = None
        if telegram_notifier.enabled:
            listener_task = asyncio.create_task(telegram_notifier.start_listener())
        ui_manager, output_file_handle = None, None
        try:
            if args.output:
                try:
                    # open in 'a+' to append and read if needed. 'a' is sufficient here.
                    output_file_handle = open(args.output, 'a', encoding='utf-8')
                    # If resuming, load existing subs from the output file to avoid duplicates
                    if args.resume:
                        output_file_handle.seek(0)
                        final_subs.update(line.strip() for line in output_file_handle if line.strip())
                except IOError as e: 
                    print(f"[-] Error opening output file {args.output}: {e}", file=sys.stderr)
                    return

            if not args.silent:
                ui_manager = UIManager(source_names, telegram_notifier, scan_state, output_file_handle)

            # MODIFIED: Pass the output file handle directly to the Scanner
            scanner = Scanner(active_sources, ui_manager, scan_state, resume_file_path, output_file=output_file_handle)

            if not scan_state.get('endpoint_scan_started'):
                completed_list = scan_state.get('completed_domains_list', [])
                if args.recursive:
                    phase1_targets = list(initial_domains - set(completed_list))
                    if phase1_targets:
                        scan_state.update({'phase': "Phase 1: Initial Scan"})
                        if ui_manager: await ui_manager.update_state_and_notify({}, force_notify=True)
                        final_subs.update(await scanner.run_scan_for_domains(phase1_targets, final_subs))
                    
                    if set(initial_domains).issubset(set(scan_state['completed_domains_list'])):
                        # NOTE: Using a copy is important here
                        recursive_base_targets = final_subs.copy() 
                        all_scanned_or_to_scan = initial_domains.union(recursive_base_targets)
                        # Re-calculate completed_list as it might have been updated during phase 1
                        completed_list = scan_state.get('completed_domains_list', [])
                        phase2_targets = list(all_scanned_or_to_scan - set(completed_list))
                        if phase2_targets:
                            scan_state.update({'phase': "Phase 2: Recursive Scan"})
                            if ui_manager: await ui_manager.update_state_and_notify({}, force_notify=True)
                            final_subs.update(await scanner.run_scan_for_domains(phase2_targets, final_subs))
                else: # Normal Mode
                    normal_targets = list(initial_domains - set(completed_list))
                    if normal_targets:
                        if ui_manager: await ui_manager.update_state_and_notify({}, force_notify=True)
                        final_subs.update(await scanner.run_scan_for_domains(normal_targets, final_subs))

            # MODIFIED: The final write is removed. The file is written incrementally.
            # We just need to close the handle if it's open.
            # The 'finally' block already handles closing the file.
            
            if not args.output and not args.silent:
                print("\n" + "-"*60)
                print("--- Final Subdomains ---")
                for sub in sorted(list(final_subs)): print(sub)
                print("-"*60)

            scan_state.update({'status': 'Complete', 'phase': 'Subdomain Scan Finished', 'endpoint_scan_started': True})
            save_state_to_yaml(scan_state, resume_file_path)
            if ui_manager: await ui_manager.update_state_and_notify({}, force_notify=True)
            
            if args.endpoint:
                if final_subs:
                    date_str = datetime.now().strftime("%Y-%m-%d")
                    endpoint_dir = f"endpoint_results_{date_str}"
                    os.makedirs(endpoint_dir, exist_ok=True)
                    print(f"\n[*] Starting Endpoint Scan. Results in '{endpoint_dir}'.")
                    grabber = EndpointGrabber(final_subs, os.path.join(endpoint_dir, "endpoints.txt"), os.path.join(endpoint_dir, "js.txt"), telegram_notifier=telegram_notifier, scan_state=scan_state)
                    await grabber.grab_endpoints()
                else:
                    print("\n[-] No subdomains to grab endpoints from.")
            
            scan_state['status'] = "Finished"
            if ui_manager: await ui_manager.update_state_and_notify({}, force_notify=True)
            
            if not args.keep_resume and resume_file_path and os.path.exists(resume_file_path):
                print(f"[*] Scan completed. Removing resume file: {resume_file_path}")
                os.remove(resume_file_path)
        finally:
            if listener_task and not listener_task.done():
                listener_task.cancel()
                await asyncio.sleep(0.1)
            if output_file_handle and not output_file_handle.closed:
                output_file_handle.close()

if __name__ == "__main__":
    try:
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(main())
    except KeyboardInterrupt:
        if sys.stdout.isatty(): sys.stdout.write("\033[?25h")
        print("\n[*] Scan interrupted by user. Rerun with --resume <file.yaml> to continue.")
    except asyncio.CancelledError:
        print("\n[*] Tasks cancelled.")
