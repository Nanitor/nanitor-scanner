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

4. Run the scanner:
```bash
sudo -E python nanscan.py
```

### Docker installation

You can use Docker to run the scanner. This has the advantage of having all the right dependencies and works out of the box.

#### Option 1: Pull the Prebuilt Image

```
docker pull ghcr.io/nanitor/nanitor-scanner:latest
docker run --rm --net=host --cap-add=NET_ADMIN \
   -e NANITOR_API_URL=https://your.nanitor.api \
   -e NANITOR_API_KEY=YourAPIKey \
   ghcr.io/nanitor/nanitor-scanner:latest
```

### Option 2: Build Locally

```
git clone https://github.com/nanitor/nanitor-scanner.git
cd nanitor-scanner
docker build -t nanitor-scanner .
docker run --rm --net=host --cap-add=NET_ADMIN \
   -e NANITOR_API_URL=https://your.nanitor.api \
   -e NANITOR_API_KEY=YourAPIKey \
   nanitor-scanner
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

## External Tools

The scanner uses the following external tools:

- `nmap`: For advanced port scanning and fingerprinting
- `gobuster`: For web directory enumeration (with a minimal word list)
- `httpx`: For web discovery

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

