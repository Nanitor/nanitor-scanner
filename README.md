# Nanitor Scanner

A comprehensive network scanning tool for security assessment and network discovery.

## System Requirements

- Python 3.8 or higher
- Nmap installed on your system
  - macOS: `brew install nmap`
  - Linux: `sudo apt-get install nmap` (Ubuntu/Debian) or `sudo yum install nmap` (RHEL/CentOS)
  - Windows: Download from [Nmap's official website](https://nmap.org/download.html)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/nanitor-scanner.git
cd nanitor-scanner
```

2. Create and activate a virtual environment (recommended):
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required Python packages:
```bash
pip install -r requirements.txt
```

## Usage

Basic usage:
```bash
python nanscan.py [options]
```

For more detailed usage information, run:
```bash
python nanscan.py --help
```

## Features

- Network discovery
- Port scanning
- OS fingerprinting
- Service banner grabbing
- SNMP information gathering
- MAC address vendor lookup
- HTTP header analysis

## Security Notice

This tool is intended for authorized network security assessment only. Unauthorized scanning of networks or systems may be illegal in your jurisdiction.

## License

[License information to be added]

## Contributing

[Contribution guidelines to be added] 