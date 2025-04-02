# Nanitor Network Scanner

A comprehensive network scanner for security assessments and discovery.

## Features

- Network discovery using ping sweep
- TCP and UDP port scanning
- MAC address and vendor resolution
- Web server detection and fingerprinting
- SSL/TLS certificate analysis
- SNMP information gathering
- Colorized terminal output
- JSON results for further analysis
- Nanitor import: Importing scan results into Nanitor

## Requirements

- **OS:** Linux (tested primarily on Linux)  
- **Python:** 3.11 
- **Privileges:** Root/admin required for some features
- **Tools:** The external tools specified in Dependencies and External tools below need to be installed.

## Installation

### From source

1. Clone the repository:
```bash
git clone https://github.com/nanitor/nanitor-scanner.git
cd nanitor-scanner
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Install the needed depencencies (nmap, gobuster, httpx).

5. Run the scanner:
```bash
sudo -E python nanscan.py
```

### Examples

Scan the local network:
```bash
sudo -E python nanscan.py
```

Scan a specific network with verbose output:
```bash
sudo -E python nanscan.py -n 192.168.1.0/24 -v
```

Import the results into Nanitor through the API. Make sure to set the environment variables, and **specify the right organization ID**.  The data will be imported into the organization specified.
```bash
export NANITOR_API_URL=https://my.nanitor.net/system_api
export NANITOR_API_KEY=MySecretAPIKeywithWritePermissionHere
python api.py import scan_results/nanitor_import.json -org-id 123
```

## Dependencies and External Tools

### Python environment

The Nanitor scanner is built in Python.  The Python configuration required is specified in the pyproject.toml.
It has a number of dependencies, as specified in requirements.txt.
For a full list of the packages and their licensing, see the [DEPENDENCIES.md](DEPENDENCIES.md) file.

### External tools

The Nanitor scanner depends on some external tools to enhance scanning capabilities. Each tool serves a specific purpose and is referenced directly for transparency and attribution:
These tools need to be installed and ready to run in the environment.

- **nmap**
  - Purpose: Advanced port scanning, OS detection, and service fingerprinting.
  - Project: [nmap/nmap on GitHub](https://github.com/nmap/nmap)
  - Maintainer: Gordon Lyon (Fyodor) and the Nmap Project
  - License: [Nmap Public Source License (based on GPLv2)](https://nmap.org/book/man-legal.html)
  - NOTE: Since nmap cannot be redistributed under its license, you need to download it and prepare it onto your system. Link: https://nmap.org/download

- **gobuster**
  - Purpose: Fast directory brute-forcing for web servers using a minimal word list.
  - Project: [OJ/gobuster on GitHub](https://github.com/OJ/gobuster)
  - Maintainer: OJ Reeves ([@TheColonial](https://github.com/OJ))
  - License: [Apache License 2.0](https://github.com/OJ/gobuster/blob/master/LICENSE)

- **httpx**
  - Purpose: Web discovery and probing for responsive HTTP servers.
  - Project: [projectdiscovery/httpx on GitHub](https://github.com/projectdiscovery/httpx)
  - Maintainer: ProjectDiscovery
  - License: [MIT License](https://github.com/projectdiscovery/httpx/blob/master/LICENSE.md)

## Future Improvements

- Unified Module Interface:
Consider refactoring scan modules to use a unified ScanContext so that each module accepts consistent inputs and returns results keyed by host IP.

- Additional Features:
Future work may include packet sniffing (e.g., DHCP requests)

## Output

Results are saved to the `scan_results` directory in the following structure:

- `scan_results/summary.json`: Overall scan summary
- `scan_results/nanitor_import.json`: Scan results ready for import via Nanitor API
- `scan_results/{ip}`: Detailed scan results for each host and tool outputs
- `scan_results/{ip}/scan_results.json`: Detailed scan results for each host

To change the output folder, use `--out-dir`.

## Feedback

If you have any feedback, feel free to contact us or submit an Issue.  If you have anything to contribute, you can open a pull request.  All pull requests will be looked at, though we may not accept everything.

