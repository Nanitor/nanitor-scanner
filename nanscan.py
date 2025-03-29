#!/usr/bin/env python3
# Standard library imports
import argparse
import json
import mdns
import os
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from ipaddress import ip_network

# Third-party imports
import psutil
import requests
import scapy.all as scapy
import urllib3
import xmltodict
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from mac_vendor_lookup import MacLookup
from pysnmp.hlapi import CommunityData, ContextData, ObjectIdentity, ObjectType, SnmpEngine, UdpTransportTarget, getCmd

# Disable insecure request warnings for HTTPS requests without certificate verification.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add constant for output verbosity level
VERBOSE_OUTPUT = False  # Set to False for cleaner output
# Add counter for progress tracking
scan_stats = {
    "hosts_found": 0,
    "hosts_scanned": 0,
    "open_tcp_ports": 0,
    "open_udp_ports": 0,
    "web_services": 0,
    "vulnerabilities": 0,
    "scan_start_time": None,
    "status_line": "",
    "lock": threading.Lock()
}

# Add these imports near the top of the file
try:
    from colorama import Back, Fore, Style, init
    # Initialize colorama
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    # Define fallback color constants if colorama is not available
    HAS_COLOR = False
    class DummyColors:
        def __getattr__(self, name):
            return ""
    Fore = DummyColors()
    Back = DummyColors()
    Style = DummyColors()

# Add this function to detect terminal color support
def supports_color():
    """Returns True if the terminal supports color, False otherwise."""
    if not HAS_COLOR:
        return False

    # Check if we're in a terminal that supports colors
    if hasattr(sys.stdout, 'isatty') and sys.stdout.isatty():
        return True

    # Check for specific environment variables
    if 'COLORTERM' in os.environ:
        return True

    # Check for specific terminals
    term = os.environ.get('TERM', '')
    if term in ('xterm', 'xterm-color', 'xterm-256color', 'linux', 'screen', 'screen-256color'):
        return True

    return False

# Set color support flag
USE_COLOR = supports_color()

# ----------------------- Configuration -----------------------
# Required system tools
REQUIRED_TOOLS = {
}

# Optional web scanning tools
SCAN_TOOLS = {
    "nmap": {
        "description": "Network mapper for port scanning and OS detection",
        "required": True,
        "install": {
            "ubuntu": "sudo apt install nmap",
            "macos": "brew install nmap"
        }
    },
    "arp": {
        "description": "ARP table management",
        "required": True,
        "install": {
            "ubuntu": "sudo apt install net-tools",
            "macos": "brew install net-tools"
        }
    },
    "httpx": {
        "description": "Modern HTTP toolkit for web scanning",
        "required": False,
        "command": "httpx -u {url} -json -silent -o {output_file} -title -status-code -tech-detect -web-server -content-length -content-type -server -cname -ip -asn -cdn",
    },
    "gobuster": {
        "description": "Directory bruteforcing",
        "required": False,
        "command": "gobuster dir -k -u {url} -w wordlists/quicklist.txt -x php,html,txt,asp,aspx,jsp,xml -r --random-agent -q -o {output_file}",
    },
    "nuclei": {
        "description": "Passive vulnerability and misconfiguration scanner",
        "required": False,
        "command": "nuclei -ni -u {url} -json-export {output_file} -severity high,critical -etags exploitation,active -silent -rate-limit 50 -concurrency 5",
    }
}

# Default values for all configurable parameters
DEFAULT_THREAD_COUNT = 10
DEFAULT_TCP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 515, 631, 1400, 1433, 1883, 3306, 3389, 5432, 5555, 5900, 6379, 7000, 8080, 8443, 9100]
DEFAULT_UDP_PORTS = [53, 67, 69, 123, 137, 161, 162, 500, 514, 520, 1900, 5353, 33434]
DEFAULT_SNMP_PORT = 161
DEFAULT_SSL_PORTS = [443, 8443]
DEFAULT_INTERFACES = ["eth0", "wlan0", "en0"]

# Global variables that can be modified by command line arguments
THREAD_COUNT = DEFAULT_THREAD_COUNT
COMMON_TCP_PORTS = DEFAULT_TCP_PORTS.copy()
COMMON_UDP_PORTS = DEFAULT_UDP_PORTS.copy()
SNMP_PORT = DEFAULT_SNMP_PORT
SSL_PORTS = DEFAULT_SSL_PORTS.copy()
ALLOWED_INTERFACES = DEFAULT_INTERFACES.copy()
# ----------------------- End Configuration -------------------


def get_local_ips_and_subnets() -> list[dict[str, str]]:
    """
    Retrieve all local IP addresses and netmasks for allowed interfaces.
    """
    ip_info = []
    for interface, addrs in psutil.net_if_addrs().items():
        if interface not in ALLOWED_INTERFACES:
            continue
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ip_info.append(
                    {"interface": interface, "ip_address": addr.address, "netmask": addr.netmask}
                )
    return ip_info


def calculate_network(ip: str, netmask: str) -> str:
    """
    Calculate the network range in CIDR notation from an IP and its netmask.
    """
    network = ip_network(f"{ip}/{netmask}", strict=False)
    return str(network)


@dataclass
class DiscoveredHost:
    ip: str
    mac: str | None = None
    vendor: str | None = None

# nmap ping discovery using nmap -sn
def nmap_ping_discovery(network: str) -> list[DiscoveredHost]:
    """
    Discover live hosts on the given network range using Nmap's ping scan.
    Returns a list of live IP addresses.
    """
    import xmltodict

    try:
        cmd = ["nmap", "-sn", "-oX", "-", network]
        process = run_subprocess_safely(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60
        )
        if process.returncode != 0:
            log_error(f"Nmap ping discovery failed: {process.stderr.strip()}")
            return []

        # Parse XML output
        nmap_data = xmltodict.parse(process.stdout)
        hosts = []
        host_entries = nmap_data.get("nmaprun", {}).get("host", [])
        if isinstance(host_entries, dict):
            host_entries = [host_entries]

        for host in host_entries:
            if host.get("status", {}).get("@state") == "up":
                ip = None
                mac = None
                vendor = None
                addresses = host.get("address", [])
                if isinstance(addresses, dict):
                    addresses = [addresses]
                for addr in addresses:
                    if addr.get("@addrtype") == "ipv4":
                        ip = addr.get("@addr")
                    elif addr.get("@addrtype") == "mac":
                        mac = addr.get("@addr")
                        vendor = addr.get("@vendor")
                if ip:
                    hosts.append(DiscoveredHost(ip=ip, mac=mac, vendor=vendor))
        return hosts
    except Exception as e:
        log_error(f"Nmap ping discovery exception: {str(e)}")
        return []


def get_arp_table() -> dict[str, str]:
    """
    Retrieve the local ARP table mapping IP addresses to MAC addresses.
    """
    try:
        arp_output = run_subprocess_safely(
            ["arp", "-a"],
            stdout=subprocess.PIPE,
            text=True,
            check=True
        ).stdout
    except Exception as e:
        print(f"Error retrieving ARP table: {e}")
        return {}
    arp_table = {}
    for line in arp_output.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            ip = parts[1].strip("()")
            mac = parts[3]
            if mac != "(incomplete)":
                arp_table[ip] = mac
    return arp_table


def resolve_mac_addresses(live_hosts: list[str]) -> dict[str, str]:
    """
    For each live host, attempt to resolve its MAC address using the ARP table
    and a Scapy ARP request as a fallback.
    """
    mac_addresses = {}
    arp_table = get_arp_table()

    for ip in live_hosts:
        if ip in arp_table:
            mac_addresses[ip] = arp_table[ip]
        else:
            arp_request = scapy.ARP(pdst=ip)
            answered, _ = scapy.srp(arp_request, timeout=2, verbose=False)
            for _sent, received in answered:
                mac_addresses[ip] = received.hwsrc
    return mac_addresses


def lookup_mac_vendor(mac: str) -> str:
    """
    Look up the vendor for a given MAC address.
    """
    if not mac:
        return "Unknown Vendor"
    mac_lookup = MacLookup()
    try:
        return mac_lookup.lookup(mac)
    except Exception:
        return "Unknown Vendor"


def lookup_mac_vendors(mac_addresses: dict[str, str]) -> dict[str, str]:
    """
    Perform MAC vendor lookups concurrently.
    """
    with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
        results = list(executor.map(lookup_mac_vendor, mac_addresses.values()))
    return dict(zip(mac_addresses.keys(), results, strict=False))


def is_root() -> bool:
    """
    Check if the script is running with root privileges.
    """
    return os.geteuid() == 0


def update_status(message=None):
    """Update the status line with current progress."""
    if not scan_stats["scan_start_time"]:
        return

    with scan_stats["lock"]:
        if message:
            scan_stats["status_line"] = message

        elapsed = datetime.now() - scan_stats["scan_start_time"]
        elapsed_str = str(timedelta(seconds=int(elapsed.total_seconds())))

        # Calculate progress percentage
        total_hosts = scan_stats["hosts_found"] or 1  # Avoid division by zero
        progress = min(100, int((scan_stats["hosts_scanned"] / total_hosts) * 100))

        # Create status line
        if USE_COLOR:
            status = f"{Fore.MAGENTA}[{elapsed_str}]{Style.RESET_ALL} "
            status += f"Progress: {Fore.CYAN}{progress}%{Style.RESET_ALL} ({scan_stats['hosts_scanned']}/{total_hosts}) | "
            status += f"TCP: {Fore.GREEN}{scan_stats['open_tcp_ports']}{Style.RESET_ALL} | "
            status += f"UDP: {Fore.GREEN}{scan_stats['open_udp_ports']}{Style.RESET_ALL} | "
            status += f"Web: {Fore.GREEN}{scan_stats['web_services']}{Style.RESET_ALL} | "
            status += f"Vulns: {Fore.YELLOW}{scan_stats['vulnerabilities']}{Style.RESET_ALL}"
            if scan_stats["status_line"]:
                status += f" | {Fore.WHITE}{scan_stats['status_line']}{Style.RESET_ALL}"
        else:
            status = f"[{elapsed_str}] "
            status += f"Progress: {progress}% ({scan_stats['hosts_scanned']}/{total_hosts}) | "
            status += f"TCP: {scan_stats['open_tcp_ports']} | UDP: {scan_stats['open_udp_ports']} | "
            status += f"Web: {scan_stats['web_services']} | Vulns: {scan_stats['vulnerabilities']}"
            if scan_stats["status_line"]:
                status += f" | {scan_stats['status_line']}"

        # Print a complete line with carriage return instead of manipulating the terminal
        # This approach doesn't leave the terminal in a weird state
        print(f"\r{status}", end='', flush=True)


def log_info(message):
    """Log an informational message."""
    # Print message on a new line
    print()  # New line
    if USE_COLOR:
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} {message}", flush=True)
    else:
        print(f"[INFO] {message}", flush=True)


def log_debug(message):
    """Log a debug message, only if verbose output is enabled."""
    if VERBOSE_OUTPUT:
        print()  # New line
        if USE_COLOR:
            print(f"{Fore.CYAN}[DEBUG]{Style.RESET_ALL} {message}", file=sys.stderr, flush=True)
        else:
            print(f"[DEBUG] {message}", file=sys.stderr, flush=True)


def log_warning(message):
    """Log a warning message."""
    print()  # New line
    if USE_COLOR:
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {message}", file=sys.stderr, flush=True)
    else:
        print(f"[WARNING] {message}", file=sys.stderr, flush=True)


def log_error(message):
    """Log an error message."""
    print()  # New line
    if USE_COLOR:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {message}", file=sys.stderr, flush=True)
    else:
        print(f"[ERROR] {message}", file=sys.stderr, flush=True)


def log_success(message):
    """Log a success message."""
    print()  # New line
    if USE_COLOR:
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {message}", flush=True)
    else:
        print(f"[SUCCESS] {message}", flush=True)


def log_phase(phase):
    """Log the start of a new scan phase."""
    print("\n" + "=" * 80, flush=True)
    if USE_COLOR:
        print(f"{Back.BLUE}{Fore.WHITE}PHASE: {phase}{Style.RESET_ALL}", flush=True)
    else:
        print(f"PHASE: {phase}", flush=True)
    print("=" * 80, flush=True)
    # Update status with phase information
    scan_stats["status_line"] = f"Phase: {phase}"


def run_subprocess_safely(cmd, **kwargs):
    """
    Run a subprocess while ensuring terminal settings are preserved.
    This function makes sure stdin is properly set to avoid terminal corruption.
    """
    # Always use these settings to prevent terminal corruption
    default_kwargs = {
        'stdin': subprocess.DEVNULL,  # Prevents terminal input mode changes
        'start_new_session': True     # Prevents signal propagation issues
    }

    # Override with any provided kwargs
    subprocess_kwargs = {**default_kwargs, **kwargs}

    # Run the subprocess with our safe settings
    return subprocess.run(cmd, **subprocess_kwargs)


# Uses nmap to do a port scan.
def port_scan(ip: str) -> dict:
    """Perform port scanning using nmap with non-blocking output."""
    open_ports = {"tcp": [], "udp": []}
    scan_type = "-sS" if is_root() else "-sT"

    try:
        update_status(f"TCP scanning {ip}")
        log_debug(f"Starting TCP port scan for {ip}...")
        # TCP Scan with -Pn to skip ping and additional options for better detection
        tcp_ports = ','.join(map(str, COMMON_TCP_PORTS))
        nmap_tcp_cmd = ["nmap", "-Pn", "-p", tcp_ports, scan_type, "--max-retries", "2", "-T4", "-oX", "-", ip]
        log_debug(f"Running TCP command: {' '.join(nmap_tcp_cmd)}")
        process = run_subprocess_safely(
            nmap_tcp_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300
        )

        log_debug(f"TCP Scan RC: {process.returncode}")
        if VERBOSE_OUTPUT:
            log_debug(f"TCP Scan STDOUT[:500]: {process.stdout[:500]}")
        if process.stderr and VERBOSE_OUTPUT:
            log_debug(f"Nmap stderr for {ip}: {process.stderr}")

        if process.returncode == 0 and process.stdout:
            # Use xmltodict to parse the XML output
            tcp_result = xmltodict.parse(process.stdout)
            # Navigate to the host and port information
            host = tcp_result.get("nmaprun", {}).get("host", {})
            ports = host.get("ports", {}).get("port", [])
            # Ensure ports is a list for consistent processing
            if isinstance(ports, dict):
                ports = [ports]
            for port in ports:
                state = port.get("state", {})
                if state.get("@state") == "open":
                    port_id = int(port.get("@portid"))
                    log_debug(f"Found open TCP port {port_id} on {ip}")
                    open_ports["tcp"].append(port_id)
                    with scan_stats["lock"]:
                        scan_stats["open_tcp_ports"] += 1
        else:
            log_debug(f"TCP Scan did not complete successfully for {ip}")

        # UDP Scan - requires root privileges
        if is_root():
            update_status(f"UDP scanning {ip}")
            log_debug(f"Starting UDP port scan for {ip}...")
            udp_ports = ','.join(map(str, COMMON_UDP_PORTS))
            nmap_udp_cmd = ["nmap", "-Pn", "-p", udp_ports, "-sU", "--max-retries", "3", "-T4", "-oX", "-", ip]
            log_debug(f"Running UDP command: {' '.join(nmap_udp_cmd)}")
            process = run_subprocess_safely(
                nmap_udp_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=600
            )

            if process.stderr and VERBOSE_OUTPUT:
                log_debug(f"Nmap UDP stderr for {ip}: {process.stderr}")

            if process.returncode == 0 and process.stdout:
                udp_result = xmltodict.parse(process.stdout)
                host = udp_result.get("nmaprun", {}).get("host", {})
                ports = host.get("ports", {}).get("port", [])
                if isinstance(ports, dict):
                    ports = [ports]
                for port in ports:
                    state = port.get("state", {})
                    if state.get("@state") == "open":
                        port_id = int(port.get("@portid"))
                        log_debug(f"Found open UDP port {port_id} on {ip}")
                        open_ports["udp"].append(port_id)
                        with scan_stats["lock"]:
                            scan_stats["open_udp_ports"] += 1
            else:
                log_debug(f"UDP Scan did not complete successfully for {ip}")
        else:
            open_ports["udp"] = "UDP scanning requires root privileges"

    except subprocess.TimeoutExpired:
        log_error(f"Port scan timed out for {ip}")
    except Exception as e:
        log_error(f"Port scan failed for {ip}: {str(e)}")

    return open_ports


def get_banner(ip: str, port: int) -> str:
    """
    Grab a service banner from the specified IP and port.
    """
    try:
        with socket.create_connection((ip, port), timeout=2) as s:
            s.send(b"\n")
            banner = s.recv(1024).decode(errors="ignore").strip()
            return banner if banner else "No banner"
    except Exception:
        return "No banner"


def get_http_headers(ip: str, port: int) -> dict[str, str]:
    """
    Retrieve HTTP headers from a service running on the given IP and port.
    """
    try:
        url = f"https://{ip}:{port}" if port == 443 else f"http://{ip}:{port}"
        response = requests.head(url, timeout=2, verify=False)
        return dict(response.headers)
    except Exception:
        return {}


def get_ssl_info(ip: str, port: int) -> dict:
    """Get SSL certificate information."""
    try:
        # Create SSL context that doesn't verify certificates
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                x509_cert = x509.load_der_x509_certificate(cert, default_backend())

                # Extract useful information
                info = {
                    "subject": {
                        k.decode('utf-8'): v.decode('utf-8')
                        for k, v in x509_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                    },
                    "issuer": {
                        k.decode('utf-8'): v.decode('utf-8')
                        for k, v in x509_cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                    },
                    "version": x509_cert.version.name,
                    "expires": x509_cert.not_valid_after.isoformat(),
                    "serial_number": hex(x509_cert.serial_number),
                    "extensions": []
                }

                # Get extensions
                for ext in x509_cert.extensions:
                    info["extensions"].append({
                        "name": ext.oid._name,
                        "value": str(ext.value)
                    })

                return info
    except ssl.SSLError as e:
        # Extract useful information from SSL errors
        error_info = {
            "error": str(e),
            "error_code": e.library,
            "error_reason": e.reason,
            "error_message": e.msg
        }

        # Try to get basic certificate info even if verification fails
        try:
            with socket.create_connection((ip, port), timeout=5) as sock:
                with ssl.wrap_socket(sock, server_hostname=ip, cert_reqs=ssl.CERT_NONE) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                    error_info["basic_info"] = {
                        "subject": {
                            k.decode('utf-8'): v.decode('utf-8')
                            for k, v in x509_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                        },
                        "issuer": {
                            k.decode('utf-8'): v.decode('utf-8')
                            for k, v in x509_cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                        },
                        "expires": x509_cert.not_valid_after.isoformat(),
                        "serial_number": hex(x509_cert.serial_number)
                    }
        except Exception:
            pass

        return error_info
    except Exception as e:
        return {"error": str(e)}


def os_fingerprint(ip: str) -> dict:
    """Detect OS using nmap with non-blocking output."""
    try:
        # Run nmap with OS detection and XML output, redirecting stdout to /dev/null
        process = run_subprocess_safely(
            ["nmap", "-O", "--max-retries", "1", "--max-scan-delay", "20s", "-oX", "-", ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=60
        )

        if process.returncode == 0 and process.stdout:
            # Parse XML output to get OS info
            import xml.etree.ElementTree as ET
            root = ET.fromstring(process.stdout)
            for host in root.findall(".//host"):
                for osmatch in host.findall(".//osmatch"):
                    return {ip: osmatch.get("name", "Unknown")}
        return {ip: "Unknown"}

    except subprocess.TimeoutExpired:
        print(f"    * OS detection timed out for {ip}", file=sys.stderr)
        return {ip: "Unknown"}
    except Exception as e:
        print(f"    * OS detection failed for {ip}: {str(e)}", file=sys.stderr)
        return {ip: "Unknown"}


def os_fingerprinting(ip_addresses: list[str]) -> dict[str, str]:
    """
    Perform OS fingerprinting on multiple hosts concurrently.
    """
    os_info = {}
    with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
        results = list(executor.map(os_fingerprint, ip_addresses))
    for result in results:
        os_info.update(result)
    return os_info


def check_dependencies():
    """Check if all required and optional scanning tools are installed."""
    missing_tools = []
    missing_optional = []

    # Check for required and optional scanning tools
    for tool, config in SCAN_TOOLS.items():
        try:
            run_subprocess_safely(["which", tool], capture_output=True, check=True)
        except subprocess.CalledProcessError:
            if config["required"]:
                missing_tools.append((tool, config))
            else:
                missing_optional.append((tool, config))

    return missing_tools, missing_optional


# TODO: Not sure if we need this, can be just in the instructions (README) and Dockerfile...
def print_installation_instructions(missing_tools, missing_optional):
    """Print installation instructions for missing tools."""
    if missing_tools:
        print("\nERROR: Required tools are missing:")
        for tool, config in missing_tools:
            print(f"- {tool}: {config['description']}")
            print("  Install with:")
            for _os_name, command in config['install'].items():
                print(f"    {command}")
        print("\nPlease install the required tools before running the scanner.")
        return False

    if missing_optional:
        print("\nWarning: Optional web scanning tools are not installed:")
        for tool, config in missing_optional:
            print(f"- {tool}: {config['description']}")
        print("\nTo install these tools:")
        print("  # On Ubuntu/Debian:")
        print("  sudo apt install " + " ".join(tool for tool, _ in missing_optional))
        print("\n  # On macOS with Homebrew:")
        print("  brew install " + " ".join(tool for tool, _ in missing_optional))
        print("\nWeb scanning features will be limited.")
        print(flush=True)

    return True


# TODO: Maybe disable this for now... Until we have a way to utilize the screenshot.
# TODO: httpx can also capture screenshots and might be better suited?
def take_webpage_screenshot(url: str, output_file: str) -> bool:
    """
    Take a screenshot of a webpage using Selenium.
    """
    try:
        print(f"Attempting to take screenshot of {url}...", file=sys.stderr)

        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
        from webdriver_manager.chrome import ChromeDriverManager

        # Set up Chrome options
        chrome_options = Options()
        chrome_options.add_argument("--headless")  # Run in headless mode
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--window-size=1024,768")
        chrome_options.add_argument("--ignore-certificate-errors")  # Ignore SSL certificate errors
        chrome_options.add_argument("--ignore-ssl-errors")  # Ignore SSL errors
        chrome_options.add_argument("--allow-insecure-localhost")  # Allow insecure localhost
        chrome_options.add_argument("--disable-web-security")  # Disable web security
        chrome_options.add_argument("--disable-features=IsolateOrigins,site-per-process")  # Disable site isolation
        chrome_options.add_argument("--disable-site-isolation-trials")  # Disable site isolation trials

        print("Initializing Chrome driver...", file=sys.stderr)

        # Initialize the driver
        service = Service(ChromeDriverManager().install())
        # Add these options to prevent terminal issues
        service_args = ['--quiet', '--log-level=3']
        service.service_args = service_args

        driver = webdriver.Chrome(
            service=service,
            options=chrome_options
        )

        try:
            print(f"Navigating to {url}...", file=sys.stderr)
            # Navigate to the URL
            driver.get(url)

            print("Waiting for page to load...", file=sys.stderr)
            # Wait for page to load
            driver.implicitly_wait(10)

            print(f"Saving screenshot to {output_file}...", file=sys.stderr)
            # Take screenshot
            driver.save_screenshot(output_file)

            # Verify the screenshot was created
            if os.path.exists(output_file):
                print(f"Screenshot successfully saved to {output_file}", file=sys.stderr)
                return True
            else:
                print(f"Failed to save screenshot to {output_file}", file=sys.stderr)
                return False

        except Exception as e:
            print(f"Error during screenshot process: {str(e)}", file=sys.stderr)
            return False
        finally:
            print("Closing Chrome driver...", file=sys.stderr)
            driver.quit()

    except ImportError as e:
        print(f"Selenium not installed: {str(e)}", file=sys.stderr)
        print("Install with: pip install selenium webdriver-manager", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Screenshot error: {str(e)}", file=sys.stderr)
        return False


# TODO: Should we have a httpx module? httpx.py ? or tool_httpx or scantool_httpx? Something like this.
# TODO: It would be good to keep the parser for httpx along with some other httpx functions, and then we can also add a test case for it...
def parse_httpx_output(output_file: str) -> dict:
    """Parse httpx JSON output into a structured format."""
    try:
        with open(output_file) as f:
            content = f.read()

        # Initialize result structure
        result = {
            "host": "",
            "ip": "",
            "port": "",
            "banner": "",
            "vulnerabilities": []
        }

        # Parse each line as JSON
        for line in content.split('\n'):
            if not line.strip():
                continue

            data = json.loads(line)

            # Extract information
            result["host"] = data.get("host", "")
            result["ip"] = data.get("ip", "")
            result["port"] = str(data.get("port", ""))
            result["banner"] = data.get("web-server", "")

            # Add security findings
            if data.get("status-code", 0) >= 400:
                result["vulnerabilities"].append({
                    "path": "/",
                    "description": f"HTTP Status Code: {data.get('status-code')}"
                })

            # Add technology information
            if data.get("tech"):
                result["vulnerabilities"].append({
                    "path": "/",
                    "description": f"Technologies: {', '.join(data.get('tech', []))}"
                })

        return result
    except Exception as e:
        print(f"Error parsing httpx output: {str(e)}", file=sys.stderr)
        return None


def parse_nuclei_output(output_file: str) -> dict:
    try:
        with open(output_file) as f:
            content = f.read().strip()

        # If content is empty, return an empty result.
        if not content:
            return {"vulnerabilities": []}

        # Check if output is a JSON array.
        if content.startswith('['):
            data = json.loads(content)  # data will be a list.
            vulnerabilities = []
            for item in data:
                vuln = {
                    "template": item.get("template", ""),
                    "info": item.get("info", {}),
                    "severity": item.get("severity", ""),
                    "matched": item.get("matched", ""),
                    "timestamp": item.get("timestamp", "")
                }
                vulnerabilities.append(vuln)
            return {"vulnerabilities": vulnerabilities}
        else:
            # Fallback: assume line-by-line JSON objects.
            result = {"vulnerabilities": []}
            for line in content.split('\n'):
                if not line.strip():
                    continue
                data = json.loads(line)
                vuln = {
                    "template": data.get("template", ""),
                    "info": data.get("info", {}),
                    "severity": data.get("severity", ""),
                    "matched": data.get("matched", ""),
                    "timestamp": data.get("timestamp", "")
                }
                result["vulnerabilities"].append(vuln)
            return result

    except Exception as e:
        print(f"Error parsing Nuclei output: {str(e)}", file=sys.stderr)
        return None


# TODO: Maybe this shouldn't be so focused on web scan? Unless web scan is done differently than some other tools use?
def run_web_scan(ip: str, port: int) -> dict:
    """Run web scanning tools on the target."""
    results = {}
    url = f"http://{ip}:{port}" if port != 443 else f"https://{ip}:{port}"

    # Create output directory if it doesn't exist
    output_dir = f"scan_results/{ip}"
    os.makedirs(output_dir, exist_ok=True)

    log_debug(f"Starting web scan for {url}")

    # First verify the port is actually open and responding
    try:
        response = requests.get(url, timeout=5, verify=False)
        log_debug(f"Port {port} is open and responding with status code {response.status_code}")
    except requests.exceptions.RequestException as e:
        log_debug(f"Port {port} is not responding: {str(e)}")
        return None

    with scan_stats["lock"]:
        scan_stats["web_services"] += 1

    # Run web scanning tools
    for tool, config in SCAN_TOOLS.items():
        if not config["command"]:
            # TODO: Maybe not the best or most explicit way to say this tool should be run...
            continue
        try:
            output_file = f"{output_dir}/{tool}_{port}.json"
            command = config["command"].format(url=url, output_file=output_file)

            update_status(f"Running {tool} on {ip}:{port}")
            log_debug(f"Running {tool} on {url}...")

            if VERBOSE_OUTPUT:
                log_debug(f"Command: {command}")

            # Run the tool using our safe subprocess wrapper
            cmd_parts = command.split()
            process = run_subprocess_safely(
                cmd_parts,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300,  # 5 minute timeout
                shell=False  # Safer to use split command than shell=True
            )

            # Print tool output for debugging
            if process.stdout and VERBOSE_OUTPUT:
                log_debug(f"{tool} stdout: {process.stdout}")
            if process.stderr and VERBOSE_OUTPUT:
                log_debug(f"{tool} stderr: {process.stderr}")

            # Check if output file was created
            if os.path.exists(output_file):
                try:
                    with open(output_file) as f:
                        content = f.read().strip()
                        # TODO: Maybe the parse_web_scan_tool_output(output, tool) or something?
                        if content:  # Only process if file has content
                            log_debug(f"Found content in {output_file}")
                            if tool == "httpx":
                                parsed_result = parse_httpx_output(output_file)
                                if parsed_result:
                                    results[tool] = {
                                        "status": "success",
                                        "output": parsed_result,
                                        "output_file": output_file
                                    }
                            elif tool == "nuclei":
                                parsed_result = parse_nuclei_output(output_file)
                                if parsed_result:
                                    results[tool] = {
                                        "status": "success",
                                        "output": parsed_result,
                                        "output_file": output_file
                                    }
                                    # Count vulnerabilities found
                                    with scan_stats["lock"]:
                                        scan_stats["vulnerabilities"] += len(parsed_result.get("vulnerabilities", []))
                            else:
                                results[tool] = {
                                    "status": "success",
                                    "output": content,
                                    "output_file": output_file
                                }
                        else:
                            log_debug(f"Output file {output_file} is empty")
                except Exception as e:
                    log_error(f"Error reading {tool} output file: {str(e)}")
            else:
                log_debug(f"{tool} did not create output file at {output_file}")

        except subprocess.TimeoutExpired:
            log_warning(f"{tool} timed out on {url}")
            continue
        except Exception as e:
            log_error(f"Error running {tool} on {url}: {str(e)}")
            continue

    # Take screenshot using Selenium
    # TODO: Do we only do the front page /, what if gobuster find sub directories?  Maybe just try to get one good shot?
    screenshot_file = f"{output_dir}/screenshot_{port}.png"
    if take_webpage_screenshot(url, screenshot_file):
        results["screenshot"] = {
            "status": "success",
            "output_file": screenshot_file
        }

    if results:
        log_debug(f"Web scan completed for {url} with {len(results)} results")
    else:
        log_debug(f"No web scan results found for {url}")

    return results if results else None


def web_scan(ip: str, ports: list[int]) -> dict:
    """Wrapper function for run_web_scan to handle multiple ports."""
    results = {}
    web_ports = [port for port in ports if port in [80, 443, 8080, 8443]]  # Only scan common web ports

    if not web_ports:
        print(f"No web ports found to scan for {ip}. Available ports: {ports}", file=sys.stderr)
        return {"message": "No web ports found to scan"}

    print(f"Scanning web ports {web_ports} on {ip}...", file=sys.stderr)

    for port in web_ports:
        try:
            print(f"Attempting web scan on port {port} for {ip}...", file=sys.stderr)
            result = run_web_scan(ip, port)
            if result:
                print(f"Successfully completed web scan on port {port} for {ip}", file=sys.stderr)
                results[port] = result
            else:
                print(f"No results from web scan on port {port} for {ip}", file=sys.stderr)
        except Exception as e:
            print(f"Error scanning web port {port} on {ip}: {str(e)}", file=sys.stderr)

    if not results:
        print(f"No web scan results found for {ip} on any ports", file=sys.stderr)
        return {"message": "No web scan results found"}

    print(f"Completed web scanning for {ip} with {len(results)} results", file=sys.stderr)
    return results


# TODO: I don't like how we are running nuclei... Nuclei doesn't specify ports, we can specify templates, or template tags.
# TODO: Possibly we should have just a map of ports to templates or template tags?
def run_nuclei_scan(target: str, port: int) -> dict:
    """Run Nuclei scan on target with support for multiple protocols."""
    try:
        # Use our project's template directory
        template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "nuclei")
        if not os.path.exists(template_dir):
            print(f"Warning: Nuclei templates not found in {template_dir}. Run 'make update-nuclei-templates' to install them.", file=sys.stderr)
            return {"error": "Templates not found"}

        results = {}

        # Determine protocol based on port
        if port in [80, 443, 8080, 8443]:
            # Web scanning
            url = f"http://{target}:{port}" if port in [80, 8080] else f"https://{target}:{port}"
            cmd = [
                "nuclei",
                "-u", url,
                "-t", template_dir,
                "-silent",
                "-no-interactsh",
                "-timeout", "5",
                "-severity", "high,critical",
                "-rate-limit", "150",
                "-bulk-size", "25",
                "-c", "50",
                "-retries", "1",
                "-project-path", "scan_results",
                "-json-export", f"scan_results/{target}_{port}_nuclei_web.json"
            ]
            result = run_subprocess_safely(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                try:
                    with open(f"scan_results/{target}_{port}_nuclei_web.json") as f:
                        results["web"] = json.load(f)
                except json.JSONDecodeError:
                    results["web"] = {"error": "Failed to parse Nuclei web output"}

        # SSH scanning
        if port == 22:
            cmd = [
                "nuclei",
                "-t", template_dir,
                "-silent",
                "-no-interactsh",
                "-timeout", "5",
                "-severity", "high,critical",
                "-rate-limit", "150",
                "-bulk-size", "25",
                "-c", "50",
                "-retries", "1",
                "-project-path", "scan_results",
                "-output", f"scan_results/{target}_{port}_nuclei_ssh.json",
                "-json-export", f"ssh://{target}:{port}"
            ]
            result = run_subprocess_safely(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                try:
                    with open(f"scan_results/{target}_{port}_nuclei_ssh.json") as f:
                        results["ssh"] = json.load(f)
                except json.JSONDecodeError:
                    results["ssh"] = {"error": "Failed to parse Nuclei SSH output"}

        # DNS scanning
        if port == 53:
            cmd = [
                "nuclei",
                "-t", template_dir,
                "-silent",
                "-no-interactsh",
                "-timeout", "5",
                "-severity", "high,critical",
                "-rate-limit", "150",
                "-bulk-size", "25",
                "-c", "50",
                "-retries", "1",
                "-project-path", "scan_results",
                "-json-export", f"scan_results/{target}_{port}_nuclei_dns.json",
                "-u", f"dns://{target}:{port}"
            ]
            result = run_subprocess_safely(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                try:
                    with open(f"scan_results/{target}_{port}_nuclei_dns.json") as f:
                        results["dns"] = json.load(f)
                except json.JSONDecodeError:
                    results["dns"] = {"error": "Failed to parse Nuclei DNS output"}

        # SNMP scanning
        if port == 161:
            cmd = [
                "nuclei",
                "-t", template_dir,
                "-json",
                "-silent",
                "-no-interactsh",
                "-timeout", "5",
                "-severity", "high,critical",
                "-rate-limit", "150",
                "-bulk-size", "25",
                "-c", "50",
                "-retries", "1",
                "-project-path", "scan_results",
                "-output", f"scan_results/{target}_{port}_nuclei_snmp.json",
                "-u", f"snmp://{target}:{port}"
            ]
            result = run_subprocess_safely(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                try:
                    with open(f"scan_results/{target}_{port}_nuclei_snmp.json") as f:
                        results["snmp"] = json.load(f)
                except json.JSONDecodeError:
                    results["snmp"] = {"error": "Failed to parse Nuclei SNMP output"}

        # FTP scanning
        if port == 21:
            cmd = [
                "nuclei",
                "-t", template_dir,
                "-json",
                "-silent",
                "-no-interactsh",
                "-timeout", "5",
                "-severity", "high,critical",
                "-rate-limit", "150",
                "-bulk-size", "25",
                "-c", "50",
                "-retries", "1",
                "-project-path", "scan_results",
                "-output", f"scan_results/{target}_{port}_nuclei_ftp.json",
                "-u", f"ftp://{target}:{port}"
            ]
            result = run_subprocess_safely(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                try:
                    with open(f"scan_results/{target}_{port}_nuclei_ftp.json") as f:
                        results["ftp"] = json.load(f)
                except json.JSONDecodeError:
                    results["ftp"] = {"error": "Failed to parse Nuclei FTP output"}

        # SMB scanning
        if port == 445:
            cmd = [
                "nuclei",
                "-t", template_dir,
                "-json",
                "-silent",
                "-no-interactsh",
                "-timeout", "5",
                "-severity", "high,critical",
                "-rate-limit", "150",
                "-bulk-size", "25",
                "-c", "50",
                "-retries", "1",
                "-project-path", "scan_results",
                "-output", f"scan_results/{target}_{port}_nuclei_smb.json",
                "-u", f"smb://{target}:{port}"
            ]
            result = run_subprocess_safely(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                try:
                    with open(f"scan_results/{target}_{port}_nuclei_smb.json") as f:
                        results["smb"] = json.load(f)
                except json.JSONDecodeError:
                    results["smb"] = {"error": "Failed to parse Nuclei SMB output"}

        return results if results else {"error": "No Nuclei results found"}

    except subprocess.TimeoutExpired:
        return {"error": "Nuclei scan timed out"}
    except Exception as e:
        return {"error": f"Nuclei scan error: {str(e)}"}


# TODO: Bit unclear what this does, is it running all the tools or not?
# TODO: I think at the moment we dont have the banners?
def scan_host(
    ip: str, mac_addresses: dict[str, str], mac_vendors: dict[str, str], os_info: dict[str, str]
) -> dict:
    """
    For a given host, perform all scanning tasks concurrently.
    Tasks include port scanning, banner grabbing, HTTP header retrieval,
    SNMP probing, and SSL certificate extraction.
    """
    update_status(f"Scanning host: {ip}")
    log_info(f"Scanning host: {ip}")
    result = {"ip": ip}
    result["mac_address"] = mac_addresses.get(ip, "N/A")
    result["mac_vendor"] = mac_vendors.get(ip, "N/A")
    result["os_info"] = os_info.get(ip, "Unknown")

    # Port scanning
    log_debug(f"  - Port scanning {ip}...")
    open_ports = port_scan(ip)
    result["open_ports"] = open_ports
    log_info(f"Host {ip}: Found {len(open_ports.get('tcp', []))} open TCP ports and {len(open_ports.get('udp', []))} open UDP ports")

    # Concurrently grab banners for all open TCP ports
    banners = {}
    tcp_ports = open_ports.get("tcp", [])
    log_info(f"Open ports: tcp: {tcp_ports}")
    if tcp_ports:
        log_info("Doing banners..")
        update_status(f"Banner grabbing for {ip}")
        log_debug(f"  - Grabbing banners for {len(tcp_ports)} open TCP ports...")
        with ThreadPoolExecutor(max_workers=len(tcp_ports)) as banner_executor:
            future_to_port = {
                banner_executor.submit(get_banner, ip, port): port for port in tcp_ports
            }
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    banners[port] = future.result()
                except Exception:
                    banners[port] = "No banner"
    else:
        log_info("No banners to check")
    result["banners"] = banners
    log_info(f"Banners: {banners}")

    # Concurrently fetch HTTP headers for common web ports (if open)
    http_headers = {}
    web_ports = [port for port in [80, 443, 8080] if port in tcp_ports]
    if web_ports:
        update_status(f"HTTP checking for {ip}")
        log_debug(f"  - Checking HTTP headers for {len(web_ports)} web ports...")
        with ThreadPoolExecutor(max_workers=len(web_ports)) as http_executor:
            future_to_port = {
                http_executor.submit(get_http_headers, ip, port): port for port in web_ports
            }
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    http_headers[port] = future.result()
                except Exception:
                    http_headers[port] = {}
    result["http_headers"] = http_headers

    # Run web scanning tools if web ports are open
    # TODO: Maybe we should call the "web scanning tools" maybe like "detailed tools" ?  We've found that the ip is reachable, and some ports open...
    if web_ports:
        update_status(f"Web scanning {ip}")
        log_debug(f"  - Running web scans for {len(web_ports)} web ports...")
        web_scan_results = {}
        for port in web_ports:
            log_debug(f"    * Scanning port {port}...")
            results = run_web_scan(ip, port)
            if results:  # Only include if we have successful results
                web_scan_results[port] = results
        if web_scan_results:  # Only include if we have any successful results
            result["web_scan_results"] = web_scan_results

    # SNMP scanning (if SNMP port is open on UDP)
    if SNMP_PORT in open_ports.get("udp", []):
        update_status(f"SNMP scanning {ip}")
        log_debug(f"  - Checking SNMP on port {SNMP_PORT}...")
        result["snmp_info"] = snmp_scan(ip, open_ports)
    else:
        result["snmp_info"] = "SNMP port not open"

    # Concurrently retrieve SSL certificate details for SSL-enabled ports
    ssl_certs = {}
    ssl_tcp_ports = [port for port in tcp_ports if port in SSL_PORTS]
    if ssl_tcp_ports:
        update_status(f"SSL scanning {ip}")
        log_debug(f"  - Checking SSL certificates for {len(ssl_tcp_ports)} SSL ports...")
        with ThreadPoolExecutor(max_workers=len(ssl_tcp_ports)) as ssl_executor:
            future_to_port = {
                ssl_executor.submit(get_ssl_info, ip, port): port for port in ssl_tcp_ports
            }
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    ssl_certs[port] = future.result()
                except Exception as e:
                    ssl_certs[port] = {"error": str(e)}
    result["ssl_certificates"] = ssl_certs if ssl_certs else "No SSL certificate info"

    with scan_stats["lock"]:
        scan_stats["hosts_scanned"] += 1

    log_success(f"Completed scanning {ip}")
    return result


def signal_handler(signum, frame):
    """Handle interrupt signals gracefully."""
    print("\nInterrupt received. Exiting...", flush=True)
    sys.exit(0)


def parse_port_list(port_string: str) -> list[int]:
    """Parse a comma-separated list of ports into integers."""
    try:
        return [int(port.strip()) for port in port_string.split(',')]
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"Invalid port number: {e}") from e


# TODO: This seems a bit redundant, we had this already somewhere...
def check_web_tools() -> dict:
    """Check if required web scanning tools are installed."""
    available_tools = {}
    for tool, info in SCAN_TOOLS.items():
        try:
            if tool == "gobuster":
                # Gobuster doesn't support --version, use help instead
                run_subprocess_safely([tool, "help"], capture_output=True, check=True)
                available_tools[tool] = {
                    "status": "installed",
                    "description": info["description"]
                }
            else:
                # Check if tool is installed
                run_subprocess_safely([tool, "--version"], capture_output=True, check=True)
                available_tools[tool] = {
                    "status": "installed",
                    "description": info["description"]
                }
        except subprocess.CalledProcessError:
            available_tools[tool] = {
                "status": "missing",
                "description": info["description"],
                "install": {
                    "ubuntu": "sudo apt install " + tool,
                    "macos": "brew install " + tool
                }
            }
        except FileNotFoundError:
            available_tools[tool] = {
                "status": "missing",
                "description": info["description"],
                "install": {
                    "ubuntu": "sudo apt install " + tool,
                    "macos": "brew install " + tool
                }
            }

    # Check for Nuclei templates
    if "nuclei" in available_tools and available_tools["nuclei"]["status"] == "installed":
        if is_root():
            print("\nWarning: Running as root. Template updates should be run as a regular user.")
            print("Please run 'make update-nuclei-templates' as a regular user to update templates.")
        else:
            try:
                # Check if templates directory exists
                if not os.path.exists("templates/nuclei"):
                    print("\nWarning: Nuclei templates not found. Run 'make update-nuclei-templates' to install them.")
            except Exception as e:
                print(f"\nWarning: Could not check Nuclei templates: {str(e)}")

    return available_tools


def save_results(live_hosts: list[DiscoveredHost], port_results, web_results, snmp_results, ssl_results, os_info, vendor_info, mdns_services=None):
    """Save scan results to JSON files."""
    # Create scan_results directory
    os.makedirs("scan_results", exist_ok=True)

    # Save individual host results
    for host in live_hosts:
        ip = host.ip
        host_dir = f"scan_results/{ip}"
        os.makedirs(host_dir, exist_ok=True)

        # Combine all results for this host
        host_results = {
            "ip": ip,
            "mac_vendor": vendor_info.get(ip, "Unknown"),
            "os_info": os_info.get(ip, "Unknown"),
            "open_ports": port_results.get(ip, {"tcp": [], "udp": []}),
            "web_scan_results": web_results.get(ip, {}),
            "snmp_info": snmp_results.get(ip, "SNMP port not open"),
            "ssl_certificates": ssl_results.get(ip, "No SSL certificate info")
        }

        # Save to JSON file
        with open(f"{host_dir}/scan_results.json", "w") as f:
            json.dump(host_results, f, indent=2)

    live_hosts_serializable = [asdict(host) for host in live_hosts]

    # Save summary results
    summary = {
        "scan_time": datetime.now().isoformat(),
        "total_hosts": len(live_hosts),
        "hosts": live_hosts_serializable,
        "os_info": os_info,
        "vendor_info": vendor_info,
        "port_results": port_results,
        "web_results": web_results,
        "snmp_results": snmp_results,
        "ssl_results": ssl_results
    }
    if mdns_services:
        summary['mdns_results'] = mdns_services

    with open("scan_results/summary.json", "w") as f:
        json.dump(summary, f, indent=4)


# Do a discovery for host, ping discovery.
def discover_live_hosts(network: str) -> list[DiscoveredHost]:
    """Scan a network for live hosts."""
    try:
        # Use ping discovery to find live hosts
        update_status(f"Discovering hosts on {network}")
        live_hosts = nmap_ping_discovery(network)
        print(f"\nlive_hosts: {live_hosts}")
        if not live_hosts:
            log_warning("No live hosts found")
            return []

        log_info(f"Discovered {len(live_hosts)} live hosts")
        return live_hosts
    except Exception as e:
        log_error(f"Error scanning network: {str(e)}")
        return []


def scan_live_hosts(live_hosts: list[str]) -> list[dict]:
    """
    For each discovered live host, resolve additional details and perform a full scan.
    Returns a list of scan results.
    """
    # Resolve MAC addresses and vendor info once for all hosts
    update_status("Resolving MAC addresses")
    mac_addresses = resolve_mac_addresses(live_hosts)
    update_status("Looking up vendor information")
    vendors = lookup_mac_vendors(mac_addresses)

    results = []
    with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
        future_to_ip = {
            executor.submit(scan_host, ip, mac_addresses, vendors, {}): ip
            for ip in live_hosts
        }
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                result = future.result()
                results.append(result)
                if not VERBOSE_OUTPUT:
                    tcp_ports = result.get("open_ports", {}).get("tcp", [])
                    udp_ports = result.get("open_ports", {}).get("udp", [])
                    vendor = result.get("mac_vendor", "Unknown")
                    log_info(
                        f"Host: {ip} ({vendor}) - TCP ports: "
                        f"{', '.join(map(str, tcp_ports)) if tcp_ports else 'None'}, UDP ports: "
                        f"{', '.join(map(str, udp_ports)) if udp_ports else 'None'}"
                    )
                else:
                    print(json.dumps(result, indent=2), flush=True)
            except Exception as e:
                log_error(f"Error scanning {ip}: {str(e)}")
    return results


def get_target_network(interfaces: list[dict[str, str]]) -> str:
    """
    Get the target network from interface information.
    Returns the network in CIDR notation.
    """
    if not interfaces:
        return None

    # Use the first interface's IP and netmask
    interface = interfaces[0]
    ip = interface["ip_address"]
    netmask = interface["netmask"]

    # Calculate network in CIDR notation
    try:
        network = calculate_network(ip, netmask)
        return network
    except Exception as e:
        print(f"Error calculating network: {str(e)}", file=sys.stderr)
        return None


# Change status updater to not use termios
def status_updater():
    """Background thread that updates the status line periodically."""
    try:
        while True:
            update_status()
            time.sleep(0.5)  # Update twice per second
    except Exception as e:
        print(f"\nStatus updater error: {str(e)}", file=sys.stderr)


def print_completion_banner(duration_str):
    """Print the scan completion banner with colors if supported."""
    print("\n\n")
    if USE_COLOR:
        print(f"{Fore.GREEN}" + "=" * 80 + f"{Style.RESET_ALL}")
        print(f"{Fore.GREEN}" + "=" * 30 + " SCAN COMPLETE " + "=" * 30 + f"{Style.RESET_ALL}")
        print(f"{Fore.GREEN}" + "=" * 80 + f"{Style.RESET_ALL}")

        # Print detailed summary
        print(f"\n{Fore.CYAN}📊 SCAN SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.WHITE}⏱️  Duration:{Style.RESET_ALL} {duration_str}")
        print(f"{Fore.WHITE}🔍 Hosts scanned:{Style.RESET_ALL} {scan_stats['hosts_scanned']} of {scan_stats['hosts_found']} discovered")
        print(f"{Fore.WHITE}🔌 Open TCP ports found:{Style.RESET_ALL} {scan_stats['open_tcp_ports']}")
        print(f"{Fore.WHITE}📡 Open UDP ports found:{Style.RESET_ALL} {scan_stats['open_udp_ports']}")
        print(f"{Fore.WHITE}🌐 Web services detected:{Style.RESET_ALL} {scan_stats['web_services']}")
        print(f"{Fore.WHITE}⚠️  Vulnerabilities found:{Style.RESET_ALL} {scan_stats['vulnerabilities']}")

        # Get timestamp for scan completion
        end_time = datetime.now()
        print(f"{Fore.WHITE}🕒 Scan completed at:{Style.RESET_ALL} {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.WHITE}💾 Results saved to:{Style.RESET_ALL} {os.path.abspath('scan_results/')}")

        # If any vulnerabilities were found, highlight them
        if scan_stats['vulnerabilities'] > 0:
            print(f"\n{Fore.RED}⚠️  ATTENTION: Vulnerabilities were detected during the scan!{Style.RESET_ALL}")
            print(f"   {Fore.YELLOW}Please review the detailed scan results for more information.{Style.RESET_ALL}")

        # Print next steps or recommendations
        print(f"\n{Fore.CYAN}📋 NEXT STEPS:{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}1. Review detailed scan results in the scan_results directory{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}2. Investigate any discovered vulnerabilities{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}3. Consider securing open ports that aren't needed{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}4. Run regular scans to monitor your network security{Style.RESET_ALL}")

        print(f"\n{Fore.GREEN}Thank you for using Nanitor Network Scanner!{Style.RESET_ALL}\n")
    else:
        print("=" * 80)
        print("=" * 30 + " SCAN COMPLETE " + "=" * 30)
        print("=" * 80)

        # Print detailed summary
        print("\n📊 SCAN SUMMARY")
        print(f"⏱️  Duration: {duration_str}")
        print(f"🔍 Hosts scanned: {scan_stats['hosts_scanned']} of {scan_stats['hosts_found']} discovered")
        print(f"🔌 Open TCP ports found: {scan_stats['open_tcp_ports']}")
        print(f"📡 Open UDP ports found: {scan_stats['open_udp_ports']}")
        print(f"🌐 Web services detected: {scan_stats['web_services']}")
        print(f"⚠️  Vulnerabilities found: {scan_stats['vulnerabilities']}")

        # Get timestamp for scan completion
        end_time = datetime.now()
        print(f"🕒 Scan completed at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"💾 Results saved to: {os.path.abspath('scan_results/')}")

        # If any vulnerabilities were found, highlight them
        if scan_stats['vulnerabilities'] > 0:
            print("\n⚠️  ATTENTION: Vulnerabilities were detected during the scan!")
            print("   Please review the detailed scan results for more information.")

        # Print next steps or recommendations
        print("\n📋 NEXT STEPS:")
        print("  1. Review detailed scan results in the scan_results directory")
        print("  2. Investigate any discovered vulnerabilities")
        print("  3. Consider securing open ports that aren't needed")
        print("  4. Run regular scans to monitor your network security")

        print("\nThank you for using Nanitor Network Scanner!\n")


def main():
    """Main function."""
    # Version information
    VERSION = "1.0.0"

    # ASCII art banner
    banner = """
    ███╗   ██╗ █████╗ ███╗   ██╗██╗████████╗ ██████╗ ██████╗
    ████╗  ██║██╔══██╗████╗  ██║██║╚══██╔══╝██╔═══██╗██╔══██╗
    ██╔██╗ ██║███████║██╔██╗ ██║██║   ██║   ██║   ██║██████╔╝
    ██║╚██╗██║██╔══██║██║╚██╗██║██║   ██║   ██║   ██║██╔══██╗
    ██║ ╚████║██║  ██║██║ ╚████║██║   ██║   ╚██████╔╝██║  ██║
    ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
    """

    # Print banner first
    print(banner)
    print(f"Version: {VERSION}")
    print("A comprehensive network scanner for security assessments and discovery")
    print("=" * 80)

    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="A comprehensive network scanner for security assessments and discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Scan local network:
    sudo -E python nanscan.py

  Scan specific network with verbose output:
    sudo -E python nanscan.py -n 192.168.1.0/24 -v

  Scan specific TCP ports:
    sudo -E python nanscan.py -n 10.0.0.0/24 --target-tcp-ports 22,80,443,8080

  Customize all scan parameters:
    sudo -E python nanscan.py -n 192.168.1.0/24 -t 20 --target-tcp-ports 22,80,443 --target-udp-ports 53,161 --ssl-ports 443,8443
        """
    )

    # Basic options
    parser.add_argument("-n", "--network",
                       help="Target network to scan (CIDR notation, e.g. 192.168.1.0/24)")
    parser.add_argument("-v", "--verbose",
                       action="store_true",
                       help="Enable verbose output")
    parser.add_argument("-t", "--threads",
                       type=int,
                       default=DEFAULT_THREAD_COUNT,
                       help=f"Number of threads (default: {DEFAULT_THREAD_COUNT})")
    parser.add_argument("-f", "--force",
                       action="store_true",
                       help="Force execution even if optional tools are missing")

    # Port scanning options
    parser.add_argument("--target-tcp-ports",
                       type=parse_port_list,
                       default=DEFAULT_TCP_PORTS,
                       help=f"TCP ports to scan (comma-separated, default: {','.join(map(str, DEFAULT_TCP_PORTS))})")
    parser.add_argument("--target-udp-ports",
                       type=parse_port_list,
                       default=DEFAULT_UDP_PORTS,
                       help=f"UDP ports to scan (comma-separated, default: {','.join(map(str, DEFAULT_UDP_PORTS))})")
    parser.add_argument("--ssl-ports",
                       type=parse_port_list,
                       default=DEFAULT_SSL_PORTS,
                       help=f"SSL/TLS ports to check (comma-separated, default: {','.join(map(str, DEFAULT_SSL_PORTS))})")
    parser.add_argument("--snmp-port",
                       type=int,
                       default=DEFAULT_SNMP_PORT,
                       help=f"SNMP port to scan (default: {DEFAULT_SNMP_PORT})")

    # Parse arguments
    args = parser.parse_args()

    # Set global variables based on command line arguments
    global VERBOSE_OUTPUT, THREAD_COUNT, COMMON_TCP_PORTS, COMMON_UDP_PORTS, SSL_PORTS, SNMP_PORT

    VERBOSE_OUTPUT = args.verbose
    THREAD_COUNT = args.threads
    COMMON_TCP_PORTS = args.target_tcp_ports
    COMMON_UDP_PORTS = args.target_udp_ports
    SSL_PORTS = args.ssl_ports
    SNMP_PORT = args.snmp_port

    if not is_root():
        print("Error: This script must be run as root for network scanning.")
        return 1

    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Initialize scan stats
    scan_stats["scan_start_time"] = datetime.now()

    # Start mDNS discovery in background with at least 10 seconds of minimum run time.
    # By default, this will listen on the meta-service to capture all service types.
    mdns_stop_event, mdns_services = mdns.run_mdns_in_background(min_duration=10)

    # Start background status updater thread
    status_thread = threading.Thread(target=status_updater, daemon=True)
    status_thread.start()

    # Get network interfaces
    interfaces = get_local_ips_and_subnets()
    if not interfaces:
        log_error("No network interfaces found.")
        return 1

    # Print startup message
    print("=" * 80)
    print("Scan configuration:")
    print("-" * 80)
    print(f"• Thread count: {THREAD_COUNT}")
    print(f"• Allowed interfaces: {', '.join(ALLOWED_INTERFACES)}")
    print(f"• TCP ports to scan: {', '.join(map(str, COMMON_TCP_PORTS))}")
    print(f"• UDP ports to scan: {', '.join(map(str, COMMON_UDP_PORTS))}")
    print(f"• SSL/TLS ports: {', '.join(map(str, SSL_PORTS))}")
    print(f"• SNMP port: {SNMP_PORT}")
    print(f"• Running as root: {is_root()}")
    print(f"• OS detection: {'Enabled' if is_root() else 'Disabled (requires root)'}")
    print(f"• Verbose output: {'Enabled' if VERBOSE_OUTPUT else 'Disabled'}")
    print("-" * 80)

    print("\nScanning tools used:")
    print("-" * 80)
    for tool, info in SCAN_TOOLS.items():
        print(f"\n{tool}:")
        print(f"  Description: {info['description']}")
        if 'command' in info:
            print(f"  Command: {info['command']}")
    print("-" * 80)

    print("\nFound network interfaces:")
    print("-" * 80)
    for interface in interfaces:
        print(f"• Interface: {interface['interface']}")
        print(f"  IP: {interface['ip_address']}")
        print(f"  Netmask: {interface['netmask']}")
    print("-" * 80)

    # Get target network - either from command line or from interfaces
    target_network = args.network if args.network else get_target_network(interfaces)
    if not target_network:
        log_error("No valid target network found.")
        return 1
    print(f"\nTarget network: {target_network}\n")

    # Perform network scan
    log_phase("NETWORK DISCOVERY")
    scan_stats["status_line"] = f"Scanning network: {target_network}"

    live_hosts = discover_live_hosts(target_network)

    if not live_hosts:
        log_warning("No live hosts found.")

        # Still show completion banner and summary
        print("\n\n")
        print("=" * 80)
        print("=" * 30 + " SCAN COMPLETE " + "=" * 30)
        print("=" * 80)

        print("\n📊 SCAN SUMMARY")
        print(f"⏱️  Duration: {str(timedelta(seconds=int((datetime.now() - scan_stats['scan_start_time']).total_seconds())))}")
        print("🔍 Hosts scanned: 0 (No live hosts found)")
        print("🔌 Open TCP ports found: 0")
        print("📡 Open UDP ports found: 0")
        print("🌐 Web services detected: 0")
        print("⚠️  Vulnerabilities found: 0")

        # Get timestamp for scan completion
        end_time = datetime.now()
        print(f"🕒 Scan completed at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")

        print("\n📋 NEXT STEPS:")
        print("  1. Verify network connectivity or try a different network range")
        print("  2. Check if hosts are blocking ICMP ping requests")
        print("  3. Try running with the -v flag for verbose output")

        print("\nThank you for using Nanitor Network Scanner!\n")

        return 0

    live_ips = [host.ip for host in live_hosts]
    #scan_results = scan_live_hosts(live_ips)
    scan_stats["hosts_found"] = len(live_ips)
    log_success(f"Found {len(live_ips)} live host(s) on {target_network}.")

    # Resolve vendor information
    # TODO: Might not be needed if we have this already from live_hosts (if nmap used ARP)
    log_phase("MAC VENDOR RESOLUTION")
    scan_stats["status_line"] = "Resolving vendor information"
    vendor_info = resolve_vendors(live_ips)

    # Perform OS detection if running as root
    os_info = {}
    if is_root():
        log_phase("OS DETECTION")
        scan_stats["status_line"] = "Performing OS detection"
        os_info = os_fingerprinting(live_ips)

    # Perform port scanning
    log_phase("PORT SCANNING")
    scan_stats["status_line"] = "Performing port scanning"
    port_results = {}
    with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
        future_to_ip = {executor.submit(port_scan, ip): ip for ip in live_ips}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                port_results[ip] = future.result()
            except Exception as e:
                log_error(f"Port scan failed for {ip}: {str(e)}")

    # Perform web scanning
    log_phase("WEB SCANNING")
    scan_stats["status_line"] = "Performing web scanning"
    web_results = {}
    with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
        future_to_ip = {
            executor.submit(web_scan, ip, port_results.get(ip, {}).get("tcp", [])): ip
            for ip in live_ips
        }
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                web_results[ip] = future.result()
            except Exception as e:
                log_error(f"Web scan failed for {ip}: {str(e)}")

    # Perform SNMP scanning
    log_phase("SNMP SCANNING")
    scan_stats["status_line"] = "Performing SNMP scanning"
    snmp_results = {}
    with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
        future_to_ip = {executor.submit(snmp_scan, ip, port_results): ip for ip in live_ips}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                snmp_results[ip] = future.result()
            except Exception as e:
                log_error(f"SNMP scan failed for {ip}: {str(e)}")

    # Perform SSL scanning
    log_phase("SSL/TLS SCANNING")
    scan_stats["status_line"] = "Performing SSL/TLS scanning"
    ssl_results = {}
    with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
        future_to_ip = {
            executor.submit(ssl_scan, ip, port_results.get(ip, {}).get("tcp", [])): ip
            for ip in live_ips
        }
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                ssl_results[ip] = future.result()
            except Exception as e:
                log_error(f"SSL scan failed for {ip}: {str(e)}")

    
    # When all scanning is complete, signal the mDNS thread to stop.
    mdns_stop_event.set()
    # Wait a moment for cleanup.
    time.sleep(1)

    # Save results
    log_phase("SAVING RESULTS")
    scan_stats["status_line"] = "Saving scan results"
    save_results(live_hosts, port_results, web_results, snmp_results, ssl_results, os_info, vendor_info, mdns_services)

    # Calculate and display scan summary
    scan_duration = datetime.now() - scan_stats["scan_start_time"]
    duration_str = str(timedelta(seconds=int(scan_duration.total_seconds())))

    # Print completion banner
    print_completion_banner(duration_str)

    # Add a newline at the end to ensure terminal prompt is clean
    print("")

    return 0


def resolve_vendors(live_hosts: list[str]) -> dict:
    """Resolve vendor information for live hosts."""
    vendor_info = {}
    # Get MAC addresses for all live hosts
    mac_addresses = resolve_mac_addresses(live_hosts)
    for ip in live_hosts:
        mac = mac_addresses.get(ip)
        if mac:
            # Look up vendor
            vendor = lookup_mac_vendor(mac)
            vendor_info[ip] = vendor
        else:
            vendor_info[ip] = "Unknown Vendor"
    return vendor_info


def snmp_scan(ip: str, port_results: dict | None = None) -> dict | None:
    """
    Perform SNMP scanning on a single host.

    Args:
        ip (str): The IP address to scan.
        port_results (dict, optional): Dictionary containing port scanning results.

    Returns:
        dict: The SNMP scan results or None if scan failed.
    """
    if USE_COLOR:
        print(f"{Fore.CYAN}[INFO] SNMP scanning {ip}{Style.RESET_ALL}")
    else:
        print(f"[INFO] SNMP scanning {ip}")

    # Check if the host has UDP port 161 open
    try:
        if (
            port_results is None or
            ip not in port_results or
            'udp' not in port_results[ip] or
            SNMP_PORT not in port_results[ip]['udp']
        ):
            if VERBOSE_OUTPUT:
                print(f"[DEBUG] Skipping SNMP scan for {ip} - port {SNMP_PORT}/udp not open")
            return {"error": f"UDP port {SNMP_PORT} not open"}
    except Exception as e:
        if VERBOSE_OUTPUT:
            print(f"[DEBUG] Error checking SNMP port for {ip}: {str(e)}")
        return {"error": f"Error checking SNMP port: {str(e)}"}

    snmp_results = {}
    community_strings = ["public", "private", "cisco", "community", "manager", "admin", "default"]

    for community in community_strings:
        try:
            system_info = get_snmp_system_info(ip, community)
            if system_info:
                snmp_results['system_info'] = system_info
                snmp_results['community_string'] = community

                if VERBOSE_OUTPUT:
                    print(f"[DEBUG] Successfully scanned {ip} with community '{community}'")
                break  # Stop trying other community strings if we succeed
            elif VERBOSE_OUTPUT:
                print(f"[DEBUG] No system info found for {ip} with community '{community}'")
        except Exception as e:
            if VERBOSE_OUTPUT:
                print(f"[DEBUG] Failed SNMP scan on {ip} with community '{community}': {str(e)}")
            continue

    if not snmp_results:
        if VERBOSE_OUTPUT:
            print(f"[DEBUG] No SNMP data found for {ip} with any community string")
        return {"error": "No SNMP data found with any community string"}

    return snmp_results


def ssl_scan(ip: str, ports: list[int]) -> dict:
    """Wrapper function for SSL scanning to handle multiple ports."""
    results = {}
    for port in ports:
        if port in SSL_PORTS:  # Only scan configured SSL ports
            try:
                result = get_ssl_info(ip, port)
                if result:
                    results[port] = result
            except Exception as e:
                log_error(f"Error scanning SSL port {port} on {ip}: {str(e)}")
    return results if results else "No SSL certificate info"


def get_snmp_system_info(ip: str, community: str) -> dict[str, str] | None:
    """
    Get system information via SNMP.

    Args:
        ip (str): Target IP address
        community (str): SNMP community string

    Returns:
        Optional[Dict[str, str]]: Dictionary containing system information or None if failed
    """
    snmp_data = {}
    oids = [
        ('1.3.6.1.2.1.1.1.0', 'sysDescr'),
        ('1.3.6.1.2.1.1.3.0', 'sysUpTime'),
        ('1.3.6.1.2.1.1.5.0', 'sysName'),
        ('1.3.6.1.2.1.1.6.0', 'sysLocation'),
        ('1.3.6.1.2.1.1.4.0', 'sysContact')
    ]

    for oid, label in oids:
        try:
            error_indication, error_status, error_index, var_binds = next(
                getCmd(
                    SnmpEngine(),
                    CommunityData(community, mpModel=0),
                    UdpTransportTarget((ip, SNMP_PORT), timeout=2, retries=1),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid))
                )
            )
            if error_indication:
                snmp_data[label] = f"Error: {error_indication}"
            elif error_status:
                snmp_data[label] = f"Error: {error_status.prettyPrint()}"
            else:
                snmp_data[label] = str(var_binds[0][1])
        except Exception as e:
            snmp_data[label] = f"SNMP error: {e}"

    return snmp_data if snmp_data else None


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
