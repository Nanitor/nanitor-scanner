# Nanitor Network Scanner

A comprehensive network scanner for security assessments and discovery.

## Features

- Network discovery using ping sweep
- TCP and UDP port scanning
- MAC address and vendor resolution
- Web server detection and fingerprinting
- SSL/TLS certificate analysis
- SNMP information gathering
- Automated vulnerability scanning with Nuclei
- Colorized terminal output
- JSON results for further analysis
- Nanitor asset import

## Requirements

- Linux (not tested on other operating systems)
- Python 3.11 or higher
- Root/admin privileges for some scanning features

## Installation

### From Source

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

4. Run the scanner:
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

Import the results into Nanitor through the API. Make sure to set the environment variables, and **specify the right organization id**.  The data will be imported into the organization specified.
```bash
export NANITOR_API_URL=https://my.nanitor.net/system_api
export NANITOR_API_KEY=MySecretAPIKeywithWritePermissionHere
python api.py import scan_results/nanitor_import.json -org-id 123
```

## External Tools

The scanner uses the following external tools:

- `nmap`: For advanced port scanning and fingerprinting
- `gobuster`: For web directory enumeration
- `httpx`: For web discovery
- `nuclei`: For automated vulnerability scanning

## Output

Results are saved to the `scan_results` directory in the following structure:

- `scan_results/summary.json`: Overall scan summary
- `scan_results/{ip}/scan_results.json`: Detailed scan results for each host
- `scan_results/{ip}/ssl/{port}.pem`: SSL certificates
- `scan_results/{ip}/snmpwalk.txt`: SNMP information
- `scan_results/nuclei/`: Nuclei scan results

To change the output folder, use `--results-dir`.

## Feedback

If you have any feedback, feel free to contact us or submit an Issue.  If you have anything to contribute, you can open a PR.  We will take a look at PRs though we might not accept everything.

