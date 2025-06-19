
<p align="center">
<img src="https://github.com/user-attachments/assets/ba942948-dce0-4bea-b7a0-8dc2f2d75caa" alt="Subtrak" width="900">
</p>

---

# SubTrak v1.0

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-brightgreen.svg)

```
 __       _    _____           _
/ _\_   _| |__/__   \_ __ __ _| | __
\ \| | | | '_ \ / /\/ '__/ _` | |/ /
_\ \ |_| | |_) / /  | | | (_| |   <
\__/\__,_|_.__/\/   |_|  \__,_|_|\_\ v1

                     ~ develop by nahid0x1 ~
```

**SubTrak** is a fast, comprehensive, and feature-rich subdomain enumeration tool written in asynchronous Python. It leverages over 70 different sources—both passive (key-less) and active (API key-based)—to discover subdomains for a given domain. Beyond simple enumeration, SubTrak includes powerful features like recursive scanning, endpoint and JavaScript file discovery, real-time Telegram notifications, and a robust resume-on-crash functionality.

---

# Why This Tool is a Superior Choice for Reconnaissance

This Python script is a comprehensive subdomain and endpoint reconnaissance tool that stands out from many popular alternatives like Subfinder, chaos-client, findomain, gau, Sublist3r, and assetfinder. Its advanced feature set and architecture provide a more powerful and holistic approach to security reconnaissance. Here’s a breakdown of its key advantages.

### 1. Unparalleled Source Aggregation

The tool integrates an extensive collection of both passive (key-less) and active (API key-based) sources to discover subdomains, far exceeding the number found in most other tools.

* **Key-less Sources (27):** It leverages a wide array of public sources that don't require API keys, including `OpenSSL_SAN`, `Google`, `Yahoo`, `Bing`, `Ask`, `Baidu`, `Netcraft`, `DNSdumpsterFree`, `GauWayback`, `GauCommoncrawl`, `GauAlienvaultOtx`, `Crtsh`, `CertspotterFree`, `BufferoverFree`, `Alienvault`, `Anubis`, `Commoncrawl`, `Digitorus`, `Hackertarget`, `Hudsonrock`, `Rapiddns`, `Sitedossier`, `Threatcrowd`, `Waybackarchive`, `Threatminer`, `Sublist3r`, and `Ctsearch`.

* **Key-based Sources (31):** For deeper and more extensive searches, it supports numerous API-driven services like `Urlscan`, `Github`, `Spyse`, `Bevigil`, `Binaryedge`, `Bufferover`, `Builtwith`, `C99`, `Censys`, `Certspotter`, `Chaos`, `ChaosPublicRecon`, `Chinaz`, `Dnsdumpster`, `Dnsrepo`, `Facebook`, `Fofa`, `Fullhunt`, `Hunter`, `Intelx`, `Leakix`, `Netlas`, `Quake`, `Redhuntlabs`, `Robtex`, `Securitytrails`, `Shodan`, `Threatbook`, `Virustotal`, `Whoisxmlapi`, `Zoomeyeapi`, and `Digitalyama`.

This vast collection ensures maximum subdomain discovery, pulling data from search engines, certificate transparency logs, DNS records, and specialized security databases.

### 2. Integrated Endpoint and JavaScript File Grabbing

Unlike tools that only find subdomains, this script goes a step further by identifying potential web endpoints and JavaScript files from the discovered assets.

* It uses external tools like `gauplus`, `waybackurls`, and `hakrawler` if they are installed on the system.
* It leverages internal API sources like `OTX` and `URLScan` to fetch known URLs.
* It includes a built-in web scraper (`js_grabber`) to parse `<script>` tags and find linked `.js` files from the subdomains' homepages.

This feature is invaluable for identifying attack surfaces beyond just the subdomains themselves.

### 3. Advanced Scanning Capabilities

* **Recursive Scanning:** The tool features a `--recursive` mode that takes the initially discovered subdomains and feeds them back into the scanning engine to find even deeper, nested subdomains. This creates a much more comprehensive map of the target's infrastructure.

* **Resume Functionality:** If a scan is interrupted, the tool automatically saves its state (including arguments and found subdomains) to a `.yaml` file. You can resume the exact same scan later using the `--resume` flag, which is critical for long-running and extensive reconnaissance tasks.

### 4. Real-time Monitoring and Control

* **Telegram Notifications:** A unique feature is the built-in Telegram integration. You can configure it to send real-time status updates of the scan directly to a chat, including progress, found subdomains, and elapsed time.
* **Remote Commands:** It even includes a listener for basic commands like `/ping`, allowing you to check if the tool is still running from your phone.

### 5. Superior UI and Output Management

* **Interactive Console UI:** In its standard mode, the script displays a clean, interactive console UI that shows the overall progress, the status of each source, and live counts of discovered assets.
* **Real-time File Writing:** Results are written to the output file incrementally as they are discovered. This prevents data loss in case the scan is unexpectedly terminated.
* **Clean and Organized Output:** Subdomains are cleaned and sanitized before being saved, removing extraneous characters or protocol prefixes for a consistent final list.

### How It Compares to Other Tools

* **Subfinder, Assetfinder, Findomain:** While these are excellent passive discovery tools, this script's source list is significantly larger, especially with the inclusion of dozens of key-based sources. They also lack built-in endpoint grabbing and recursive scanning.
* **Chaos-client:** This client is limited to the ProjectDiscovery Chaos dataset. Our script uses Chaos as just one of its many sources, providing far broader coverage.
* **Gau, Waybackurls:** These tools are focused on fetching URLs from archives. This script incorporates their functionality as part of its more extensive endpoint-grabbing feature.
* **Sublist3r:** Sublist3r is a classic tool, but its source list is smaller and it is not as actively maintained. This script has already integrated the Sublist3r API as one of its many sources.
* **Github-subdomain:** This functionality is already built into our script's powerful `Github` source class, which searches code for potential subdomains.

In conclusion, this script is not just a subdomain finder; it's an all-in-one reconnaissance framework. By combining a massive number of sources with endpoint grabbing, recursive logic, and modern features like resume functionality and Telegram notifications, it offers a more powerful, comprehensive, and user-friendly solution than most specialized tools available today.

---

## Key Features

- **Massive Source Coverage**: Utilizes over 70 distinct sources for subdomain discovery, including search engines, certificate transparency logs, and dozens of third-party APIs.
- **Asynchronous & Fast**: Built with `asyncio` and `aiohttp` for high-concurrency and maximum speed.
- **Interactive UI**: A clean, dynamic terminal interface that provides real-time status on all running sources, progress bars, and live statistics.
- **Recursive Scanning**: Can perform multi-level recursive scans, feeding newly found subdomains back into the engine to discover even more assets.
- **Endpoint & JS Grabbing**: After finding subdomains, it can automatically scan them to discover known URLs and JavaScript files using both internal and external tools.
- **Telegram Integration**: Get real-time scan progress updates, status changes, and final results sent directly to your Telegram chat. You can even send commands back to the running tool.
- **Resume Functionality**: If a scan is interrupted (manually or by a crash), it can be resumed exactly where it left off, saving all previously discovered data.
- **Flexible Input & Output**: Scan a single domain, a list of domains from a file, and save results to a specified output file.
- **Smart API Key Management**: Automatically uses any API keys you provide in the configuration, skipping sources for which no key is available.
- **Silent Mode**: Disable the interactive UI for easy integration into automated workflows and scripting.

## Demo

Here is a preview of the interactive terminal UI during a scan:

```plaintext
🚀 Scan Mode: Recursive | Status: Running (Phase 1: Initial Scan)
   └─ Target: example.com (1/1)

  [alienvault          ] Found 45.
  [anubis              ] Found 5.
  [ask                 ] Running...
  [baidu               ] No results.
  [bevigil             ] No results.
  [bing                ] Running...
  [binaryedge          ] Found 12.
  [bufferover          ] No results.
  [builtwith           ] No API key.
  [c99                 ] No API key.
  [censys              ] Found 88.
  [chaos               ] Found 103.
  ...and so on...
------------------------------------------------------------
  Phase Progress: [█████████████████████████─────────] 75.20%
  Overall Domains Scanned: 1/1 (100.00%)
  Total Unique Subs: 1542 | Elapsed: 45.81s
```

## Installation

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/nahid0x1/SubTrak.git
    cd SubTrak
    ```

2.  **Install Python Dependencies**
    ```bash
    pip3 install aiohttp beautifulsoup4 PyYAML
    ```


3.  **Install External Tools (Optional)**
    For the best results with the `--endpoint` feature, install these popular Go tools:
    - [gauplus](https://github.com/bp0lr/gauplus)
    - [waybackurls](https://github.com/tomnomnom/waybackurls)
    - [hakrawler](https://github.com/hakluke/hakrawler)

    Make sure they are in your system's `PATH`.

## Configuration

SubTrak's power is maximized by using API keys. Edit the `subtrak.py` file to add your keys and configure notifications.

### 1. API Keys

Open `subtrak.py` and locate the `API_KEYS` dictionary. Add your keys for any supported service.

```python
# --- API KEY CONFIGURATION ---
API_KEYS = {
    "bevigil": [],
    "binaryedge": [],
    # ...
    "chaos": ["YOUR_CHAOS_API_KEY_HERE"],
    # ...
    "github": ["YOUR_GITHUB_PAT_HERE"],
    # ...
    "shodan": ["YOUR_SHODAN_API_KEY_HERE"],
    "virustotal": ["YOUR_VIRUSTOTAL_API_KEY_HERE"],
    # ... etc
}
```

### 2. Telegram Notifications

To enable Telegram notifications, set `"enabled": True` and provide your bot's API token and your chat ID.

```python
# --- TELEGRAM BOT CONFIGURATION ---
TELEGRAM_CONFIG = {
    "enabled": True,
    "api_token": "YOUR_TELEGRAM_BOT_API_TOKEN",
    "chat_id": "YOUR_TELEGRAM_CHAT_ID"
}
```
You can send `/ping` to your bot to check if it's connected and listening.

## Usage

The script is highly flexible. Here are the most common use cases.

### Command-line Arguments

```
usage: subtrak.py [-h] [-o OUTPUT] [-s] [--sources] [--recursive] [--endpoint] [--endpoint-sources] [--keep-resume]
              (domain | -l LIST | --resume RESUME)

Required:
  domain                Single domain to scan.
  -l, --list LIST       File of domains to scan.
  --resume RESUME       Resume a previous scan from a YAML state file.

Options:
  -h, --help            Show this help message and exit.
  -o, --output FILE     File to save results. Subdomains are appended in real-time.
  -s, --silent          Silent mode (no console UI or banner).
  --recursive           Enable recursive scanning on found subdomains.
  --endpoint            Grab known URLs and JS files after subdomain scan.
  --keep-resume         Do not delete the resume file on successful completion.
  --sources             List all available subdomain sources and exit.
  --endpoint-sources    List all available endpoint/JS sources and exit.
```

### Examples

**1. Scan a Single Domain**
```bash
python subtrak.py example.com
```

**2. Scan a Single Domain and Save Results**
Results are saved to the file in real-time.
```bash
python subtrak.py example.com -o example_subs.txt
```

**3. Scan a List of Domains from a File**
```bash
python subtrak.py -l domains.txt -o all_subs.txt
```

**4. Perform a Recursive Scan**
This will first scan the initial domain(s), then take all found subdomains and scan them as well.
```bash
python subtrak.py example.com --recursive
```

**5. Find Subdomains and then Discover Endpoints/JS Files**
This runs the full workflow: find subdomains, then find associated URLs and JS files. Endpoint results are saved in a new directory (`endpoint_results_YYYY-MM-DD/`).
```bash
python subtrak.py example.com --endpoint -o subs.txt
```

**6. Resume an Interrupted Scan**
If the script is stopped, it leaves a `resume_YYYY-MM-DD_HH-MM-SS.yaml` file. You can continue the scan with:
```bash
python subtrak.py --resume resume_2023-10-27_10-30-00.yaml
```
The resume feature will automatically restore your original settings (like output file and scan mode).

**7. Run in Silent Mode**
Perfect for automation. No UI is printed, only the final results to stdout (if `-o` is not used).
```bash
python subtrak.py example.com -s -o subs.txt
```

**8. List Available Sources**
To see all the enumeration sources SubTrak supports:
```bash
python subtrak.py --sources
```

## Supported Sources

SubTrak integrates a vast number of sources to ensure maximum discovery.

#### Key-Based Sources (API Required)
`bevigil`, `binaryedge`, `bufferover`, `builtwith`, `c99`, `censys`, `certspotter`, `chaos`, `chaospublicrecon`, `chinaz`, `dnsdumpster`, `dnsrepo`, `facebook`, `fofa`, `fullhunt`, `github`, `hunter`, `intelx`, `leakix`, `netlas`, `quake`, `redhuntlabs`, `robtex`, `securitytrails`, `shodan`, `spyse`, `threatbook`, `virustotal`, `whoisxmlapi`, `zoomeyeapi`, `digitalyama`, `urlscan`.

#### Key-Less (Passive) Sources
`openssl_san`, `google`, `yahoo`, `bing`, `ask`, `baidu`, `netcraft`, `dnsdumpster_free`, `gau_wayback`, `gau_commoncrawl`, `gau_alienvault_otx`, `crtsh`, `certspotter_free`, `bufferover_free`, `alienvault`, `anubis`, `commoncrawl`, `digitorus`, `hackertarget`, `hudsonrock`, `rapiddns`, `sitedossier`, `threatcrowd`, `waybackarchive`, `threatminer`, `sublist3r`, `ctsearch`.


## 🌟 Contributors


<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/0xraselrana"><img src="https://avatars.githubusercontent.com/u/77453792?v=4?s=100" width="100px;" alt="Md. Rasel Rana"/><br /><sub><b>Md. Rasel Rana</b></sub></a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/the5orcerer"><img src="https://avatars.githubusercontent.com/u/97868096?v=4?s=100" width="100px;" alt="Abu Hurayra"/><br /><sub><b>Abu Hurayra</b></sub></a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/0xh7ml"><img src="https://avatars.githubusercontent.com/u/42938253?v=4?s=100" width="100px;" alt="Md Saikat"/><br /><sub><b>Md Saikat</b></sub></a></td>
    </tr>

  </tbody>
</table>

# Author
- **GitHub**: [@nahid0x1](https://github.com/nahid0x1)
- **Twitter**: [@nahid0x1](https://x.com/nahid0x1)
- **Linkedin**: [@nahid0x1](https://www.linkedin.com/in/nahid0x1)
- **Email**: [nahid0x1.official@gmail.com](mailto:nahid0x1.official@gmail.com)
