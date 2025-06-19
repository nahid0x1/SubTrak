
<p align="center">
<img src="https://github.com/user-attachments/assets/ba942948-dce0-4bea-b7a0-8dc2f2d75caa" alt="Subtrak" width="250">
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
    git clone https://github.com/your-username/SubTrak.git
    cd SubTrak
    ```

2.  **Install Python Dependencies**
    SubTrak requires a few Python libraries. You can install them using pip:
    ```bash
    pip install aiohttp beautifulsoup4 PyYAML
    ```
    The script will notify you if a dependency is missing.

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


## Acknowledgments

- Developed with passion by **nahid0x1**.
- Inspired by the open-source security community and the need for comprehensive, all-in-one enumeration tools.
