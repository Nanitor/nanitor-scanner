#!/usr/bin/env python3

# TODO:
# 4. Modularize more scanners.
# 5. Add packet sniffing capture (esp. DHCP requests)
# 8. Ability to upload directly to Nanitor's API (NANITOR_INSTANCE_URL, NANITOR_API_KEY or NANITOR_API_URL/KEY?)
# 1. TODO: make use of scan modules (we have fancy: get_scan_modules)
# 1. Update the README...
# 1. Provide a Dockerfile and make commands to build...
# 1. Setup CI with linting, and some runs... (not sure if we can run it on github.. or if we can mock something,
#    maybe just run it on the local machine or something, not perfect, but something.....)
# 1. Banner, http header results...
# 1. Carify VERBOSE_OUTPUT vs DEBUG_MODE and add debug mode as a flag, or just use verbose?
# 10. Eliminate TODOs


# Standard library imports
import argparse
import json
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from datetime import datetime, timedelta
from ipaddress import ip_network
from pathlib import Path

# Local imports
from models import DiscoveredHost
from api import convert_scan_results_to_nanitor_import
import mdns

# Third-party imports
import psutil
import requests
import scapy.all as scapy
import urllib3
import xmltodict
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
from mac_vendor_lookup import MacLookup
from pysnmp.hlapi import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    getCmd,
)

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
    "lock": threading.Lock(),
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
    if hasattr(sys.stdout, "isatty") and sys.stdout.isatty():
        return True

    # Check for specific environment variables
    if "COLORTERM" in os.environ:
        return True

    # Check for specific terminals
    term = os.environ.get("TERM", "")
    if term in (
        "xterm",
        "xterm-color",
        "xterm-256color",
        "linux",
        "screen",
        "screen-256color",
    ):
        return True

    return False


# Set color support flag
USE_COLOR = supports_color()

# ----------------------- Configuration -----------------------
# Scanning tools used. Some are required, some optional.
SCAN_TOOLS = {
    "nmap": {
        "description": "Network mapper for port scanning and OS detection",
        "required": True,
    },
    "arp": {
        "description": "ARP table management",
        "required": True,
    },
    "httpx": {
        "description": "Modern HTTP toolkit for web scanning",
        "required": False,
    },
    "gobuster": {
        "description": "Web directory enumeration",
        "required": False,
    },
}


# Definition of scan modules that are done.
# TODO: We're currently not using this, but we would like to use this, possibly streamlining the flow through such definitions
def get_scan_modules():
    return {
        "nmap_host_discovery": {
            "description": "Host discovery and ping sweep to discover live hosts using nmap (nmap -sn)",
            "required": True,
            "root_required": False,
            "required_tools": ["nmap"],
            "function": discover_live_hosts,  # network
        },
        "port_scan": {
            "description": "TCP/UDP port scanning using nmap",
            "required": True,
            "root_required": True,
            "required_tools": ["nmap"],
            "function": port_scan,  # ip
        },
        "os_fingerprint": {
            "description": "OS fingerprinting with Nmap",
            "required": False,
            "root_required": True,
            "required_tools": ["nmap"],
            "function": os_fingerprinting,  # ip_addresses
        },
        "httpx": {
            "description": "Web header and technology scan",
            "required": False,
            "root_required": False,
            "required_tools": ["httpx"],
            "function": httpx_scan,  # ip,port
        },
        "gobuster": {
            "description": "Directory enumeration with a quick wordlist",
            "required": False,
            "root_required": False,
            "required_tools": ["gobuster"],
            "function": gobuster_scan,  # (ip,port)
        },
        "ssl_scan": {
            "description": "Scan for SSL/TLS certs",
            "required": False,
            "root_required": False,
            "required_tools": [],
            "function": ssl_scan,  # (ip, ports)
        },
        "snmp_scan": {
            "description": "Scan for SNMP info",
            "required": False,
            "root_required": False,
            "required_tools": [],
            "function": snmp_scan,  # (ip, port_results)
        },
    }


# Default values for all configurable parameters
DEFAULT_THREAD_COUNT = 10
DEFAULT_TCP_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    515,
    631,
    1400,
    1433,
    1883,
    3306,
    3389,
    5432,
    5555,
    5900,
    6379,
    7000,
    8080,
    8443,
    9100,
]
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
DEBUG_MODE = True  # Used to skip the prompt so that one can use tools like pdb without interference.
WEB_PORTS = [80, 443, 8080, 8443]
RESULTS_DIR = "scan_results"
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
                    {
                        "interface": interface,
                        "ip_address": addr.address,
                        "netmask": addr.netmask,
                    }
                )
    return ip_info


def calculate_network(ip: str, netmask: str) -> str:
    """
    Calculate the network range in CIDR notation from an IP and its netmask.
    """
    network = ip_network(f"{ip}/{netmask}", strict=False)
    return str(network)


# nmap ping discovery using nmap -sn
def nmap_ping_discovery(network: str) -> list[DiscoveredHost]:
    """
    Discover live hosts on the given network range using Nmap's ping scan.
    Returns a list of live IP addresses.
    """
    import xmltodict

    try:
        cmd = ["nmap", "-sn", "-oX", "-", network]
        process = run_subprocess_safely(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
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
                hostname_list = []
                if isinstance(addresses, dict):
                    addresses = [addresses]
                for addr in addresses:
                    if addr.get("@addrtype") == "ipv4":
                        ip = addr.get("@addr")
                    elif addr.get("@addrtype") == "mac":
                        mac = addr.get("@addr")
                        vendor = addr.get("@vendor")
                # ---- Parse <hostnames> for a PTR or other hostname ----
                hostnames_block = host.get("hostnames", {})
                if isinstance(hostnames_block, dict):
                    # 'hostname' might be a dict or a list of dicts
                    h = hostnames_block.get("hostname", [])
                    if isinstance(h, dict):
                        h = [h]  # unify into a list
                    for hn in h:
                        # Example: hn = {"@name": "huawei", "@type": "PTR"}
                        name = hn.get("@name")
                        if name:
                            hostname_list.append(name)
                hostnames = hostname_list if hostname_list else None
                if ip:
                    hosts.append(DiscoveredHost(ip=ip, mac=mac, vendor=vendor, hostnames=hostnames))
        return hosts
    except Exception as e:
        log_error(f"Nmap ping discovery exception: {str(e)}")
        return []


def get_arp_table() -> dict[str, str]:
    """
    Retrieve the local ARP table mapping IP addresses to MAC addresses.
    """
    try:
        arp_output = run_subprocess_safely(["arp", "-a"], stdout=subprocess.PIPE, text=True, check=True).stdout
    except Exception as e:
        log_error(f"Error retrieving ARP table: {e}")
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
    if DEBUG_MODE:
        return
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
        print(f"\r{status}", end="", flush=True)


# Use print_lock to control printing on screen by potentially multiple threads.
print_lock = threading.Lock()


def log_info(message):
    """Log an informational message."""
    with print_lock:
        if USE_COLOR:
            print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} {message}", flush=True)
        else:
            print(f"[INFO] {message}", flush=True)


def log_debug(message):
    """Log a debug message, only if verbose output is enabled."""
    if VERBOSE_OUTPUT:
        with print_lock:
            if USE_COLOR:
                print(
                    f"{Fore.CYAN}[DEBUG]{Style.RESET_ALL} {message}",
                    file=sys.stderr,
                    flush=True,
                )
            else:
                print(f"[DEBUG] {message}", file=sys.stderr, flush=True)


def log_warning(message):
    """Log a warning message."""
    with print_lock:
        if USE_COLOR:
            print(
                f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {message}",
                file=sys.stderr,
                flush=True,
            )
        else:
            print(f"[WARNING] {message}", file=sys.stderr, flush=True)


def log_error(message):
    """Log an error message."""
    with print_lock:
        if USE_COLOR:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {message}", file=sys.stderr, flush=True)
        else:
            print(f"[ERROR] {message}", file=sys.stderr, flush=True)


def log_success(message):
    """Log a success message."""
    with print_lock:
        if USE_COLOR:
            print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {message}", flush=True)
        else:
            print(f"[SUCCESS] {message}", flush=True)


def log_phase(phase):
    """Log the start of a new scan phase."""
    with print_lock:
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
        "stdin": subprocess.DEVNULL,  # Prevents terminal input mode changes
        "start_new_session": True,  # Prevents signal propagation issues
    }

    # Override with any provided kwargs
    subprocess_kwargs = {**default_kwargs, **kwargs}

    # Run the subprocess with our safe settings
    return subprocess.run(cmd, **subprocess_kwargs)


def run_tasks_in_parallel(
    func,
    tasks,
    key_field="ip",
    max_workers=THREAD_COUNT,
    task_label=None,
    accumulate=False,
):
    """
    Run a function concurrently over a list of tasks.

    Args:
        func: The function to execute. It may accept arguments as unpacked from each task dict.
        tasks (list[dict]): A list of task dictionaries. Each must contain the key key_field.
        key_field (str): The field in each task to use as the result key.
        max_workers (int): Maximum number of threads to use.
        task_label (str, optional): A friendly label for the task (default is func.__name__).
        accumulate (bool): If True, accumulate multiple results per key into a list.

    Returns:
        dict: A mapping of each task’s key (task[key_field]) to the result of func(**task).
              If accumulate is True, each value is a list of results.
    """
    if task_label is None:
        task_label = func.__name__
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_key = {}
        for task in tasks:
            key = task.get(key_field)
            if key is None:
                raise ValueError(f"Task {task} is missing the required key field '{key_field}'")
            future = executor.submit(func, **task)
            future_to_key[future] = key
        for future in as_completed(future_to_key):
            key = future_to_key[future]
            try:
                res = future.result()
                if accumulate:
                    results.setdefault(key, []).append(res)
                else:
                    results[key] = res
            except Exception as e:
                error_msg = f"{task_label} failed for {key}: {e.__class__.__name__} - {str(e)}"
                log_error(error_msg)
                if accumulate:
                    results.setdefault(key, []).append({"error": error_msg})
                else:
                    results[key] = {"error": error_msg}
    return results


# Uses nmap to do a port scan.
def port_scan(ip: str) -> dict:
    """Perform port scanning using nmap with non-blocking output."""
    open_ports = {"tcp": [], "udp": []}
    scan_type = "-sS" if is_root() else "-sT"

    try:
        update_status(f"TCP scanning {ip}")
        log_debug(f"Starting TCP port scan for {ip}...")
        # TCP Scan with -Pn to skip ping and additional options for better detection
        tcp_ports = ",".join(map(str, COMMON_TCP_PORTS))
        nmap_tcp_cmd = [
            "nmap",
            "-Pn",
            "-p",
            tcp_ports,
            scan_type,
            "--max-retries",
            "2",
            "-T4",
            "-oX",
            "-",
            ip,
        ]
        log_debug(f"Running TCP command: {' '.join(nmap_tcp_cmd)}")
        process = run_subprocess_safely(
            nmap_tcp_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,
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
            udp_ports = ",".join(map(str, COMMON_UDP_PORTS))
            nmap_udp_cmd = [
                "nmap",
                "-Pn",
                "-p",
                udp_ports,
                "-sU",
                "--max-retries",
                "3",
                "-T4",
                "-oX",
                "-",
                ip,
            ]
            log_debug(f"Running UDP command: {' '.join(nmap_udp_cmd)}")
            process = run_subprocess_safely(
                nmap_udp_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=600,
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


def http_header_scan(ip: str, port: int) -> dict:
    """Perform an HTTP header scan on the given IP and port, with error handling."""
    try:
        headers = get_http_headers(ip, port)
        # Ensure we return an empty dict if headers is falsy
        return {"port": port, "headers": headers if headers else {}}
    except Exception as e:
        log_debug(f"HTTP header scan failed for {ip}:{port}: {e}")
        return {"port": port, "headers": {}}


def banner_scan(ip: str, port: int) -> dict:
    """
    Perform a banner scan on the given IP and port.
    Returns a dict with 'port' and 'banner'.
    """
    try:
        with socket.create_connection((ip, port), timeout=2) as s:
            s.sendall(b"\n")
            banner = s.recv(1024).decode(errors="ignore").strip()
            return {"port": port, "banner": banner if banner else "No banner"}
    except Exception as e:
        log_debug(f"Banner scan failed for {ip}:{port}: {e}")
        return {"port": port, "banner": "No banner"}


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

    result = {}
    # First, check if the certificate passes validation using a verifying context.
    try:
        # This context will perform certificate validation.
        valid_context = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=5) as sock:
            with valid_context.wrap_socket(sock, server_hostname=ip) as ssock:
                # If no exception occurs, the certificate is valid.
                result["validation"] = "passed"
    except Exception as e:
        # If there is an error, mark the certificate as failing validation.
        result["validation"] = f"failed: {str(e)}"

    # Now, extract certificate information using an insecure context, to capture invalid certificates also.
    try:
        # Create SSL context that doesn't verify certificates (insecure). Since we want to capture the information.
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                x509_cert = x509.load_der_x509_certificate(cert, default_backend())

                result["subject"] = x509_cert.subject.rfc4514_string()
                result["issuer"] = x509_cert.issuer.rfc4514_string()
                result["version"] = x509_cert.version.name
                result["expires"] = x509_cert.not_valid_after_utc.isoformat()
                result["serial_number"] = hex(x509_cert.serial_number)
                result["extensions"] = []
                # Process extensions
                for ext in x509_cert.extensions:
                    if ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                        # Extract DNS names from SAN extension
                        dns_names = ext.value.get_values_for_type(x509.DNSName)
                        result["extensions"].append({"name": "subjectAltName", "value": dns_names})

                return result
    except Exception as e:
        result["error"] = str(e)
        return result


def os_fingerprint(ip: str) -> dict:
    """Detect OS using nmap with non-blocking output."""
    try:
        # Run nmap with OS detection and XML output, redirecting stdout to /dev/null
        process = run_subprocess_safely(
            [
                "nmap",
                "-O",
                "--max-retries",
                "1",
                "--max-scan-delay",
                "20s",
                "-oX",
                "-",
                ip,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=60,
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
        log_info(f"    * OS detection timed out for {ip}")
        return {ip: "Unknown"}
    except Exception as e:
        log_info(f"    * OS detection failed for {ip}: {str(e)}")
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

    for tool, config in SCAN_TOOLS.items():
        if shutil.which(tool) is None:
            if config["required"]:
                missing_tools.append((tool, config))
            else:
                missing_optional.append((tool, config))

    return missing_tools, missing_optional


def print_tools_used_summary(scan_mode, skip_tools=None):
    print("\nTools used:")
    print("-" * 80)
    if skip_tools is None:
        skip_tools = set()

    for tool, config in SCAN_TOOLS.items():
        path = shutil.which(tool)
        required = config.get("required", False)

        if path is None:
            status = "✗ (missing)"
        elif tool in skip_tools:
            status = "✓ (skipped)"
        elif scan_mode == "minimal" and config.get("root_required", False):
            status = "✓ (minimal)"
        else:
            status = f"✓ (used - {path})"

        if required:
            status += " - required"

        print(f"• {tool:<12} {status}")
    print("-" * 80)


def take_webpage_screenshot(url: str, output_file: str) -> bool:
    """
    Take a screenshot of a webpage using Selenium.
    """
    try:
        log_info(f"Attempting to take screenshot of {url}...")

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

        log_info("Initializing Chrome driver...")

        # Initialize the driver
        service = Service(ChromeDriverManager().install())
        # Add these options to prevent terminal issues
        service_args = ["--quiet", "--log-level=3"]
        service.service_args = service_args

        driver = webdriver.Chrome(service=service, options=chrome_options)

        try:
            log_debug(f"Navigating to {url}...")
            # Navigate to the URL
            driver.get(url)

            log_debug("Waiting for page to load...")
            # Wait for page to load
            driver.implicitly_wait(10)

            log_debug(f"Saving screenshot to {output_file}...")
            # Take screenshot
            driver.save_screenshot(output_file)

            # Verify the screenshot was created
            if os.path.exists(output_file):
                log_debug(f"Screenshot successfully saved to {output_file}")
                return True
            else:
                log_debug(f"Failed to save screenshot to {output_file}")
                return False

        except Exception as e:
            log_warning(f"Error during screenshot process: {str(e)}")
            return False
        finally:
            log_debug("Closing Chrome driver...")
            driver.quit()

    except ImportError as e:
        log_warning(f"Selenium not installed: {str(e)}")
        log_info("Install with: pip install selenium webdriver-manager")
        return False
    except Exception as e:
        log_error(f"Screenshot error: {str(e)}")
        return False


def parse_httpx_output(output_file: str) -> dict:
    """Parse httpx JSON output into a structured format."""
    try:
        with open(output_file) as f:
            content = f.read().strip()
        if not content:
            return {}
        data = json.loads(content)
        result = {
            "timestamp": data.get("timestamp", ""),
            "cdn": data.get("cdn", ""),
            "cdn_name": data.get("cdn_name", ""),
            "cdn_type": data.get("cdn_type", ""),
            "method": data.get("method", ""),
            "url": data.get("url", ""),
            "host": data.get("host", ""),
            "ip": data.get("ip", data.get("host", "")),
            "port": str(data.get("port", "")),
            "scheme": data.get("scheme", ""),
            "webserver": data.get("webserver", ""),
            "content_type": data.get("content_type", ""),
            "content_length": data.get("content_length", ""),
            "status_code": data.get("status_code", ""),
            "location": data.get("location", ""),
            "favicon": data.get("favicon", ""),
            "hash": data.get("hash", ""),
            "jarm": data.get("jarm", ""),
            "tech": data.get("tech", ""),
            "cname": data.get("cname", ""),
            "asn": data.get("asn", ""),
            "knowledgebase": data.get("knowledgebase", {}),
            "title": data.get("title", ""),
            "body_preview": data.get("body_preview", ""),
        }
        return result
    except Exception as e:
        log_error(f"Error parsing httpx output: {str(e)}")
        return {}


def run_web_scans(ip: str, ports: list[int]) -> dict:
    results = {}
    # Only consider web ports
    web_ports = [p for p in ports if p in WEB_PORTS]
    if not web_ports:
        return {"message": "No web ports found"}
    for port in web_ports:
        # For each tool, call its scan function independently:
        results["gobuster"] = gobuster_scan(ip, port)
        results["httpx"] = httpx_scan(ip, port)
    return results


def gobuster_scan(ip: str, port: int) -> dict:
    """
    Run gobuster for directory bruteforcing on the given IP and port.
    Returns a dict with the gobuster results.
    """
    url = f"http://{ip}:{port}" if port not in [443, 8443] else f"https://{ip}:{port}"
    output_dir = Path(f"{RESULTS_DIR}/{ip}")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"gobuster_{port}.json"

    # Build the command directly
    # (Adjust the wordlist path as needed.)
    command = [
        "gobuster",
        "dir",
        "-k",
        "-u",
        url,
        "-w",
        "contrib/wordlists/quicklist.txt",
        "-x",
        "php,html,txt,asp,aspx,jsp,xml",
        "-r",
        "--random-agent",
        "-q",
        "-o",
        str(output_file),
    ]
    try:
        proc = run_subprocess_safely(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,
        )
        if proc.returncode != 0:
            return {"error": f"Gobuster failed: {proc.stderr.strip()}"}
    except Exception as e:
        return {"error": f"Gobuster execution error: {str(e)}"}

    if not output_file.exists() or output_file.stat().st_size == 0:
        return {"error": "No output from gobuster"}

    # Parse the output using our dedicated parser
    parsed = parse_gobuster_output(str(output_file))
    return parsed


def parse_gobuster_output(file_path: str) -> dict:
    """
    Parse gobuster output from the given file and return a dictionary
    with a list of results.

    Expected format per line:
      /login.html           (Status: 200) [Size: 5844]

    Returns:
      {
         "results": [
             {"path": "/login.html", "status": 200, "size": 5844},
             {"path": "/robots.txt", "status": 200, "size": 27}
         ]
      }
    """
    results = []
    # This regex expects the path to start with '/' followed by non-whitespace characters,
    # then some whitespace, then "(Status:" followed by digits, then ") [Size:" and digits, then "]"
    pattern = re.compile(r"^(?P<path>/\S+)\s+\(Status:\s*(?P<status>\d+)\)\s+\[Size:\s*(?P<size>\d+)\]")
    try:
        with open(file_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                match = pattern.match(line)
                if match:
                    entry = {"path": match.group("path"), "status": int(match.group("status")), "size": int(match.group("size"))}
                    results.append(entry)
                else:
                    # Optionally log or handle lines that don't match
                    print(f"Warning: Unrecognized line format: {line}", file=sys.stderr)
        return {"results": results}
    except Exception as e:
        print(f"Error parsing gobuster output file {file_path}: {e}", file=sys.stderr)
        return {"error": str(e)}


def httpx_scan(ip: str, port: int) -> dict:
    """
    Run httpx for HTTP scanning on the given IP and port.
    Returns a dict with parsed httpx output.
    """
    url = f"http://{ip}:{port}" if port != 443 else f"https://{ip}:{port}"
    output_dir = Path(f"scan_results/{ip}")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"httpx_{port}.json"

    # Build the command directly.
    command = [
        "httpx",
        "-u",
        url,
        "-json",
        "-silent",
        "-o",
        str(output_file),
        "-title",
        "-body-preview",
        "-favicon",
        "-status-code",
        "-tech-detect",
        "-web-server",
        "-content-length",
        "-content-type",
        "-server",
        "-cname",
        "-ip",
        "-asn",
        "-cdn",
    ]
    try:
        proc = run_subprocess_safely(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,
        )
        if proc.returncode != 0:
            return {"error": f"httpx failed: {proc.stderr.strip()}"}
    except Exception as e:
        return {"error": f"httpx execution error: {str(e)}"}

    try:
        # Here we assume parse_httpx_output is defined elsewhere.
        result = parse_httpx_output(str(output_file))
        return {"status": "success", "output": result}
    except Exception as e:
        return {"error": f"Error parsing httpx output: {str(e)}"}


def signal_handler(signum, frame):
    """Handle interrupt signals gracefully."""
    log_info("\nInterrupt received. Exiting...", flush=True)
    sys.exit(0)


def parse_port_list(port_string: str) -> list[int]:
    """Parse a comma-separated list of ports into integers."""
    try:
        return [int(port.strip()) for port in port_string.split(",")]
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"Invalid port number: {e}") from e


def save_results(
    live_hosts: list[DiscoveredHost],
    port_results,
    web_results,
    snmp_results,
    ssl_results,
    os_info,
    vendor_info,
    mdns_services=None,
):
    """Save scan results to JSON files."""
    # Create scan_results directory
    os.makedirs(RESULTS_DIR, exist_ok=True)

    # Save individual host results
    for host in live_hosts:
        ip = host.ip
        host_dir = f"{RESULTS_DIR}/{ip}"
        os.makedirs(host_dir, exist_ok=True)

        # Combine all results for this host
        host_results = {
            "ip": ip,
            "mac_vendor": vendor_info.get(ip, "Unknown"),
            "os_info": os_info.get(ip, "Unknown"),
            "open_ports": port_results.get(ip, {"tcp": [], "udp": []}),
            "web_scan_results": web_results.get(ip, {}),
            "snmp_info": snmp_results.get(ip, "SNMP port not open"),
            "ssl_certificates": ssl_results.get(ip, "No SSL certificate info"),
        }
        if mdns_services:
            host_results = mdns.add_mdns_results_to_host(mdns_services, host_results)

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
        "ssl_results": ssl_results,
    }
    if mdns_services:
        summary["mdns_results"] = mdns_services

    with open(f"{RESULTS_DIR}/summary.json", "w") as f:
        json.dump(summary, f, indent=4)


# Do a discovery for host, ping discovery.
def discover_live_hosts(network: str) -> list[DiscoveredHost]:
    """Scan a network for live hosts."""
    try:
        # Use ping discovery to find live hosts
        update_status(f"Discovering hosts on {network}")
        live_hosts = nmap_ping_discovery(network)
        log_info(f"live_hosts: {live_hosts}")
        if not live_hosts:
            log_warning("No live hosts found")
            return []

        log_info(f"Discovered {len(live_hosts)} live hosts")
        return live_hosts
    except Exception as e:
        log_error(f"Error scanning network: {str(e)}")
        return []


# Do all scans on all live hosts (ips).
def run_all_scans(live_hosts: list[DiscoveredHost]) -> dict:
    """
    Orchestrate all scanning steps for a list of DiscoveredHost objects.
    Returns a dictionary containing all results, e.g.:
    {
      "os_info": {...},
      "port_results": {...},
      "web_results": {...},
      "snmp_results": {...},
      "ssl_results": {...},
      "vendor_info": {...}
    }
    """
    # 1) Collect IPs
    ips = [h.ip for h in live_hosts]

    # 2) Resolve vendor info
    # (Potentially optional if you already have vendor info from Nmap's MAC.)
    log_phase("MAC VENDOR RESOLUTION")
    scan_stats["status_line"] = "Resolving vendor information"
    vendor_info = resolve_vendors(ips)

    # 3) OS detection
    # TODO: os_fingerprinting is rolling its own threading, probably clean that up and use run_tasks_in_parallel...
    os_info = {}
    if is_root():
        log_phase("OS DETECTION")
        scan_stats["status_line"] = "Performing OS detection"
        os_info = os_fingerprinting(ips)

    # 4) Port scanning
    log_phase("PORT SCANNING")
    scan_stats["status_line"] = "Performing port scanning"
    # For port scanning, each task is simply: {"ip": ip}
    port_tasks = [{"ip": ip} for ip in ips]
    port_results = run_tasks_in_parallel(port_scan, port_tasks)

    # Banner scanning/grabbing
    # For each IP, for each open TCP port, grab a banner.
    log_phase("BANNER GRABBING from open tcp ports")
    scan_stats["status_line"] = "Performing banner grabbing"
    banner_tasks = []
    for ip in ips:
        tcp_ports = port_results.get(ip, {}).get("tcp", [])
        for port in tcp_ports:
            banner_tasks.append({"ip": ip, "port": port})
    total_banner_tasks = len(banner_tasks)
    unique_banner_ips = len({task["ip"] for task in banner_tasks})
    log_info(f"Banner scan: Processing {total_banner_tasks} tasks across {unique_banner_ips} unique IPs.")
    banner_results = run_tasks_in_parallel(
        banner_scan,
        banner_tasks,
        key_field="ip",
        task_label="Banner scan",
        accumulate=True,
    )
    # Merge banner results into port_results under the "banners" key.
    for ip in ips:
        if ip in port_results:
            port_results[ip]["banners"] = banner_results.get(ip, None)
        else:
            port_results[ip] = {"banners": banner_results.get(ip, None)}

    # HTTP header scanning.
    log_phase("HTTP HEADERS SCANNING")
    scan_stats["status_line"] = "Retrieving HTTP headers"
    http_header_tasks = [{"ip": ip, "port": port} for ip in ips for port in WEB_PORTS if port in port_results.get(ip, {}).get("tcp", [])]
    http_header_results = run_tasks_in_parallel(http_header_scan, http_header_tasks)

    # 5) Web scanning
    # TODO: Only if has http ports?
    log_phase("WEB SCANNING")
    scan_stats["status_line"] = "Performing web scanning"
    web_tasks = [{"ip": ip, "ports": port_results.get(ip, {}).get("tcp", [])} for ip in ips]
    web_results = run_tasks_in_parallel(run_web_scans, web_tasks, key_field="ip")

    # 6) SNMP scanning
    log_phase("SNMP SCANNING")
    scan_stats["status_line"] = "Performing SNMP scanning"
    snmp_tasks = [{"ip": ip, "port_results": port_results} for ip in ips]
    snmp_results = run_tasks_in_parallel(snmp_scan, snmp_tasks)

    # 7) SSL scanning
    log_phase("SSL/TLS SCANNING")
    scan_stats["status_line"] = "Performing SSL/TLS scanning"
    ssl_tasks = [{"ip": ip, "ports": port_results.get(ip, {}).get("tcp", [])} for ip in ips]
    ssl_results = run_tasks_in_parallel(ssl_scan, ssl_tasks)

    return {
        "vendor_info": vendor_info,
        "os_info": os_info,
        "port_results": port_results,
        "http_headers": http_header_results,
        "web_results": web_results,
        "snmp_results": snmp_results,
        "ssl_results": ssl_results,
    }


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
        log_error(f"Error calculating network: {str(e)}")
        return None


# Change status updater to not use termios
def status_updater():
    """Background thread that updates the status line periodically."""
    try:
        while True:
            update_status()
            time.sleep(0.5)  # Update twice per second
    except Exception as e:
        log_error(f"\nStatus updater error: {str(e)}")


def colorize(text: str, color: str) -> str:
    """Return text wrapped in color codes if USE_COLOR is True, otherwise return plain text."""
    return f"{color}{text}{Style.RESET_ALL}" if USE_COLOR else text


def print_completion_banner(duration_str: str, import_file: str):
    """
    Print the final scan completion banner with a consistent format,
    including the scan summary and instructions for importing the Nanitor JSON.

    Assumes the following globals are available:
      - scan_stats: A dict containing scan summary details.
      - RESULTS_DIR: The directory where results are saved.
      - USE_COLOR, Fore, Style: For color formatting.
    """
    from datetime import datetime
    import os

    print("\n\n")

    # Header
    header = "=" * 80
    print(colorize(header, Fore.GREEN))
    print(colorize("=" * 30 + " SCAN COMPLETE " + "=" * 30, Fore.GREEN))
    print(colorize(header, Fore.GREEN))
    print("")

    # Scan summary details
    print(colorize("📊 SCAN SUMMARY", Fore.CYAN))
    print(colorize(f"⏱️  Duration: {duration_str}", Fore.WHITE))
    print(colorize(f"🔍 Hosts scanned: {scan_stats['hosts_scanned']} of {scan_stats['hosts_found']} discovered", Fore.WHITE))
    print(colorize(f"🔌 Open TCP ports found: {scan_stats['open_tcp_ports']}", Fore.WHITE))
    print(colorize(f"📡 Open UDP ports found: {scan_stats['open_udp_ports']}", Fore.WHITE))
    print(colorize(f"🌐 Web services detected: {scan_stats['web_services']}", Fore.WHITE))
    print(colorize(f"⚠️  Vulnerabilities found: {scan_stats['vulnerabilities']}", Fore.WHITE))

    end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(colorize(f"🕒 Scan completed at: {end_time}", Fore.WHITE))
    print(colorize(f"💾 Results saved to: {os.path.abspath(RESULTS_DIR)}", Fore.WHITE))
    print(colorize(f"Nanitor import JSON saved to: {os.path.abspath(import_file)}", Fore.WHITE))
    print("")

    # Nanitor import JSON details and instructions
    print(colorize("To import the results into your Nanitor instance, run:", Fore.GREEN))
    print(colorize(f"  python api.py import {os.path.abspath(import_file)} --org-id <YOUR_ORGANIZATION_ID>", Fore.YELLOW))
    print("")

    if scan_stats["vulnerabilities"] > 0:
        print(colorize("⚠️  ATTENTION: Vulnerabilities were detected during the scan!", Fore.RED))
        print(colorize("   Please review the detailed scan results for more information.", Fore.YELLOW))
        print("")

    # Final thank you message
    print(colorize("Thank you for using Nanitor Network Scanner!", Fore.WHITE))
    print(colorize("If you encounter any issues or have any requests, please submit an issue on our GitHub repo:", Fore.WHITE))
    print(colorize("https://github.com/nanitor/nanitor-scanner", Fore.WHITE))
    print("")


def main():
    """Main function."""
    # Version information
    VERSION = "0.1.0"

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
        """,
    )

    # Basic options
    parser.add_argument(
        "-n",
        "--network",
        help="Target network to scan (CIDR notation, e.g. 192.168.1.0/24)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=DEFAULT_THREAD_COUNT,
        help=f"Number of threads (default: {DEFAULT_THREAD_COUNT})",
    )
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Force execution even if optional tools are missing",
    )
    parser.add_argument(
        "--minimal",
        action="store_true",
        help="Run in minimal mode (non-root): skips or degrades root-required modules like UDP and OS fingerprinting.",
    )
    parser.add_argument(
        "--out-dir",
        default="scan_results",
        help="Directory to save scan results (default: scan_results/)",
    )

    # Port scanning options
    parser.add_argument(
        "--target-tcp-ports",
        type=parse_port_list,
        default=DEFAULT_TCP_PORTS,
        help=f"TCP ports to scan (comma-separated, default: {','.join(map(str, DEFAULT_TCP_PORTS))})",
    )
    parser.add_argument(
        "--target-udp-ports",
        type=parse_port_list,
        default=DEFAULT_UDP_PORTS,
        help=f"UDP ports to scan (comma-separated, default: {','.join(map(str, DEFAULT_UDP_PORTS))})",
    )
    parser.add_argument(
        "--ssl-ports",
        type=parse_port_list,
        default=DEFAULT_SSL_PORTS,
        help=f"SSL/TLS ports to check (comma-separated, default: {','.join(map(str, DEFAULT_SSL_PORTS))})",
    )
    parser.add_argument(
        "--snmp-port",
        type=int,
        default=DEFAULT_SNMP_PORT,
        help=f"SNMP port to scan (default: {DEFAULT_SNMP_PORT})",
    )

    # Parse arguments
    args = parser.parse_args()

    # Set global variables based on command line arguments
    global VERBOSE_OUTPUT, THREAD_COUNT, COMMON_TCP_PORTS, COMMON_UDP_PORTS, SSL_PORTS, SNMP_PORT, RESULTS_DIR

    VERBOSE_OUTPUT = args.verbose
    THREAD_COUNT = args.threads
    COMMON_TCP_PORTS = args.target_tcp_ports
    COMMON_UDP_PORTS = args.target_udp_ports
    SSL_PORTS = args.ssl_ports
    SNMP_PORT = args.snmp_port
    RESULTS_DIR = args.out_dir

    if is_root():
        scan_mode = "root"
    elif args.minimal:
        scan_mode = "minimal"
    else:
        print("Error: This script must be run as root for network scanning (use --minimal to force a run that skips UDP, OS fingerprinting and other root-required features).")
        return 1

    missing_required, missing_optional = check_dependencies()
    # Fail if required tools are missing
    if missing_required:
        log_error("Missing required tools (please install):")
        for tool, cfg in missing_required:
            log_error(f"  - {tool}: {cfg['description']}")
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
    if not DEBUG_MODE:
        status_thread = threading.Thread(target=status_updater, daemon=True)
        status_thread.start()

    # Get network interfaces
    interfaces = get_local_ips_and_subnets()
    if not interfaces:
        log_error("No network interfaces found.")
        return 1

    config_items = [
        ("Scan mode", scan_mode),
        ("Thread count", THREAD_COUNT),
        ("Allowed interfaces", ", ".join(ALLOWED_INTERFACES)),
        ("TCP ports to scan", ", ".join(map(str, COMMON_TCP_PORTS))),
        (
            "UDP ports to scan",
            "Skipped (requires root)" if scan_mode == "minimal" else ", ".join(map(str, COMMON_UDP_PORTS)),
        ),
        ("SSL/TLS ports", ", ".join(map(str, SSL_PORTS))),
        ("SNMP port", SNMP_PORT),
        ("Running as root", "Yes" if is_root() else "No"),
        (
            "OS detection",
            "Skipped (requires root)" if scan_mode == "minimal" else "Enabled",
        ),
        ("Verbose output (debug)", "Enabled" if VERBOSE_OUTPUT else "Disabled"),
        ("Results directory", os.path.abspath(RESULTS_DIR)),
    ]

    # Print startup message
    print("=" * 80)
    print("Scan configuration:")
    print("-" * 80)
    for label, value in config_items:
        print(f"• {label:<20}: {value}")
    print("-" * 80)

    print_tools_used_summary(scan_mode)

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
    scan_stats["hosts_found"] = len(live_ips)
    log_success(f"Found {len(live_ips)} live host(s) on {target_network}.")

    # 2) Orchestrate all scanning
    scan_results = run_all_scans(live_hosts)

    # When all scanning is complete, signal the mDNS thread to stop.
    mdns_stop_event.set()
    # Wait a moment for cleanup.
    time.sleep(1)

    # Convert to IP -> mdns results dictionary format.
    scan_results["mdns_results"] = mdns.map_mdns_results_by_ip(mdns_services)

    # Save results
    log_phase("SAVING RESULTS")
    scan_stats["status_line"] = "Saving scan results"
    # TODO: Banner, http header results?
    save_results(
        live_hosts,
        scan_results["port_results"],
        scan_results["web_results"],
        scan_results["snmp_results"],
        scan_results["ssl_results"],
        scan_results["os_info"],
        scan_results["vendor_info"],
        mdns_services,
    )

    # Convert the scan results into Nanitor's import format.
    import_payload = convert_scan_results_to_nanitor_import(
        live_hosts,
        scan_results,
        organization_id=None,  # We don't know the organization id yet. It needs to be populated before importing.
    )
    # Save the converted JSON to a file, e.g., nanitor_import.json.
    import_file = os.path.join(RESULTS_DIR, "nanitor_import.json")
    with open(import_file, "w") as f:
        json.dump(import_payload, f, indent=4)

    log_success(f"Nanitor import JSON saved to {import_file}")

    # Calculate and display scan summary
    scan_duration = datetime.now() - scan_stats["scan_start_time"]
    duration_str = str(timedelta(seconds=int(scan_duration.total_seconds())))

    # Print completion banner
    print_completion_banner(duration_str, import_file)

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
    log_info(f"SNMP scanning {ip}")
    # Check if the host has UDP port 161 open
    try:
        if port_results is None or ip not in port_results or "udp" not in port_results[ip] or SNMP_PORT not in port_results[ip]["udp"]:
            log_debug(f"[DEBUG] Skipping SNMP scan for {ip} - port {SNMP_PORT}/udp not open")
            return {"error": f"UDP port {SNMP_PORT} not open"}
    except Exception as e:
        log_debug(f"[DEBUG] Error checking SNMP port for {ip}: {str(e)}")
        return {"error": f"Error checking SNMP port: {str(e)}"}

    snmp_results = {}
    community_strings = [
        "public",
        "private",
        "cisco",
        "community",
        "manager",
        "admin",
        "default",
    ]

    for community in community_strings:
        try:
            system_info = get_snmp_system_info(ip, community)
            if system_info:
                snmp_results["system_info"] = system_info
                snmp_results["community_string"] = community
                log_debug(f"[DEBUG] Successfully scanned {ip} with community '{community}'")
                break  # Stop trying other community strings if we succeed
            elif VERBOSE_OUTPUT:
                log_debug(f"[DEBUG] No system info found for {ip} with community '{community}'")
        except Exception as e:
            if VERBOSE_OUTPUT:
                log_debug(f"[DEBUG] Failed SNMP scan on {ip} with community '{community}': {str(e)}")
            continue

    if not snmp_results:
        if VERBOSE_OUTPUT:
            log_debug(f"[DEBUG] No SNMP data found for {ip} with any community string")
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
        ("1.3.6.1.2.1.1.1.0", "sysDescr"),
        ("1.3.6.1.2.1.1.3.0", "sysUpTime"),
        ("1.3.6.1.2.1.1.5.0", "sysName"),
        ("1.3.6.1.2.1.1.6.0", "sysLocation"),
        ("1.3.6.1.2.1.1.4.0", "sysContact"),
    ]

    for oid, label in oids:
        try:
            error_indication, error_status, error_index, var_binds = next(
                getCmd(
                    SnmpEngine(),
                    CommunityData(community, mpModel=0),
                    UdpTransportTarget((ip, SNMP_PORT), timeout=2, retries=1),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid)),
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
