#!/usr/bin/env python3
# Standard library imports
import argparse
import json
import os
import signal
import socket
import ssl
import subprocess
import sys
import termios
import tty
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_network
from datetime import datetime

# Third-party imports
import nmap
import psutil
import requests
import scapy.all as scapy
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from mac_vendor_lookup import MacLookup
from ping3 import ping
import urllib3
from pysnmp.hlapi import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    getCmd,
)
import xmltodict

# Disable insecure request warnings for HTTPS requests without certificate verification.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ----------------------- Configuration -----------------------
# Required system tools
REQUIRED_TOOLS = {
    "nmap": {
        "description": "Network mapper for port scanning and OS detection",
        "install": {
            "ubuntu": "sudo apt install nmap",
            "macos": "brew install nmap"
        }
    },
    "arp": {
        "description": "ARP table management",
        "install": {
            "ubuntu": "sudo apt install net-tools",
            "macos": "brew install net-tools"
        }
    }
}

# Optional web scanning tools
WEB_SCAN_TOOLS = {
    "httpx": {
        "command": "httpx -u {url} -json -silent -o {output_file} -title -status-code -tech-detect -web-server -content-length -content-type -server -cname -ip -asn -cdn",
        "description": "Modern HTTP toolkit for web scanning",
        "features": [
            "Title detection",
            "Status code checking",
            "Technology detection",
            "Web server identification",
            "Content type analysis",
            "SSL/TLS information",
            "CDN detection",
            "ASN information"
        ]
    },
    "gobuster": {
        "command": "gobuster dir -k -u {url} -w wordlists/quicklist.txt -x php,html,txt,asp,aspx,jsp,xml -r --random-agent -q -o {output_file}",
        "description": "Directory bruteforcing",
        "wordlist": "wordlists/quicklist.txt"
    },
    "nuclei": {
        "command": "nuclei -ni -u {url} -json-export {output_file} -severity high,critical -etags exploitation,active -silent -rate-limit 50 -concurrency 5",
        "description": "Passive vulnerability and misconfiguration scanner"
    }
}

# Default values for all configurable parameters
DEFAULT_THREAD_COUNT = 10
DEFAULT_TCP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 1433, 1883, 3306, 3389, 5432, 5555, 5900, 6379, 8080, 8443]
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


def ping_host(ip: str) -> str:
    """
    Ping a single IP to see if it is alive.
    """
    try:
        if ping(ip, timeout=1) is not None:
            return ip
    except Exception:
        pass
    return None


def ping_discovery(network: str) -> list[str]:
    """
    Discover live hosts on the given network range via parallel pinging.
    """
    net = ip_network(network, strict=False)
    with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
        results = list(executor.map(ping_host, [str(ip) for ip in net.hosts()]))
    return [ip for ip in results if ip]


def get_arp_table() -> dict[str, str]:
    """
    Retrieve the local ARP table mapping IP addresses to MAC addresses.
    """
    try:
        arp_output = subprocess.check_output(["arp", "-a"], universal_newlines=True)
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


def port_scan(ip: str) -> dict:
    """Perform port scanning using nmap with non-blocking output."""
    open_ports = {"tcp": [], "udp": []}
    scan_type = "-sS" if is_root() else "-sT"

    try:
        print(f"    * Starting TCP port scan for {ip}...", file=sys.stderr)
        # TCP Scan with -Pn to skip ping and additional options for better detection
        tcp_ports = ','.join(map(str, COMMON_TCP_PORTS))
        nmap_tcp_cmd = ["nmap", "-Pn", "-p", tcp_ports, scan_type, "--max-retries", "2", "-T4", "-oX", "-", ip]
        print(f"    * Running TCP command: {' '.join(nmap_tcp_cmd)}", file=sys.stderr)
        process = subprocess.run(
            nmap_tcp_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,  # Capture stderr for debugging
            text=True,
            timeout=300
        )

        print(f"    * TCP Scan RC: {process.returncode}", file=sys.stderr)
        print(f"    * TCP Scan STDOUT[:500]: {process.stdout[:500]}", file=sys.stderr)
        if process.stderr:
            print(f"    * Nmap stderr for {ip}: {process.stderr}", file=sys.stderr)
        
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
                    print(f"    * Found open TCP port {port_id} on {ip}", file=sys.stderr)
                    open_ports["tcp"].append(port_id)
        else:
            print(f"    * TCP Scan did not complete successfully for {ip}", file=sys.stderr)

        # UDP Scan - requires root privileges
        if is_root():
            print(f"    * Starting UDP port scan for {ip}...", file=sys.stderr)
            udp_ports = ','.join(map(str, COMMON_UDP_PORTS))
            nmap_udp_cmd = ["nmap", "-Pn", "-p", udp_ports, "-sU", "--max-retries", "3", "-T4", "-oX", "-", ip]
            print(f"    * Running UDP command: {' '.join(nmap_udp_cmd)}", file=sys.stderr)
            process = subprocess.run(
                nmap_udp_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=600
            )
            
            if process.stderr:
                print(f"    * Nmap UDP stderr for {ip}: {process.stderr}", file=sys.stderr)
            
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
                        print(f"    * Found open UDP port {port_id} on {ip}", file=sys.stderr)
                        open_ports["udp"].append(port_id)
            else:
                print(f"    * UDP Scan did not complete successfully for {ip}", file=sys.stderr)
        else:
            open_ports["udp"] = "UDP scanning requires root privileges"

    except subprocess.TimeoutExpired:
        print(f"    * Port scan timed out for {ip}", file=sys.stderr)
    except Exception as e:
        print(f"    * Port scan failed for {ip}: {str(e)}", file=sys.stderr)

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
        process = subprocess.run(
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
    """Check if all required tools are installed."""
    missing_tools = []
    missing_optional = []
    
    # Check required tools
    for tool, config in REQUIRED_TOOLS.items():
        try:
            subprocess.run(["which", tool], capture_output=True, check=True)
        except subprocess.CalledProcessError:
            missing_tools.append((tool, config))
    
    # Check optional web scanning tools
    for tool, config in WEB_SCAN_TOOLS.items():
        try:
            subprocess.run(["which", tool], capture_output=True, check=True)
        except subprocess.CalledProcessError:
            missing_optional.append((tool, config))
    
    return missing_tools, missing_optional


def print_installation_instructions(missing_tools, missing_optional):
    """Print installation instructions for missing tools."""
    if missing_tools:
        print("\nERROR: Required tools are missing:")
        for tool, config in missing_tools:
            print(f"- {tool}: {config['description']}")
            print("  Install with:")
            for os_name, command in config['install'].items():
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
        driver = webdriver.Chrome(
            service=Service(ChromeDriverManager().install()),
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


def parse_httpx_output(output_file: str) -> dict:
    """Parse httpx JSON output into a structured format."""
    try:
        with open(output_file, 'r') as f:
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
        with open(output_file, 'r') as f:
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


def run_web_scan(ip: str, port: int) -> dict:
    """Run web scanning tools on the target."""
    results = {}
    url = f"http://{ip}:{port}" if port != 443 else f"https://{ip}:{port}"
    
    # Create output directory if it doesn't exist
    output_dir = f"scan_results/{ip}"
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"Starting web scan for {url}", file=sys.stderr)
    
    # First verify the port is actually open and responding
    try:
        response = requests.get(url, timeout=5, verify=False)
        print(f"Port {port} is open and responding with status code {response.status_code}", file=sys.stderr)
    except requests.exceptions.RequestException as e:
        print(f"Port {port} is not responding: {str(e)}", file=sys.stderr)
        return None
    
    # Run web scanning tools
    for tool, config in WEB_SCAN_TOOLS.items():
        try:
            output_file = f"{output_dir}/{tool}_{port}.json"
            command = config["command"].format(url=url, output_file=output_file)
            
            print(f"Running {tool} on {url}...", file=sys.stderr)
            print(f"Command: {command}", file=sys.stderr)
            
            # Run the tool with shell=True and proper environment
            process = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                env={**os.environ, 'PATH': '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin'}  # Ensure PATH includes Homebrew
            )
            
            # Print tool output for debugging
            if process.stdout:
                print(f"{tool} stdout: {process.stdout}", file=sys.stderr)
            if process.stderr:
                print(f"{tool} stderr: {process.stderr}", file=sys.stderr)
            
            # Check if output file was created
            if os.path.exists(output_file):
                try:
                    with open(output_file, 'r') as f:
                        content = f.read().strip()
                        if content:  # Only process if file has content
                            print(f"Found content in {output_file}", file=sys.stderr)
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
                            else:
                                results[tool] = {
                                    "status": "success",
                                    "output": content,
                                    "output_file": output_file
                                }
                        else:
                            print(f"Output file {output_file} is empty", file=sys.stderr)
                except Exception as e:
                    print(f"Error reading {tool} output file: {str(e)}", file=sys.stderr)
            else:
                print(f"{tool} did not create output file at {output_file}", file=sys.stderr)
            
        except subprocess.TimeoutExpired:
            print(f"{tool} timed out on {url}", file=sys.stderr)
            continue
        except Exception as e:
            print(f"Error running {tool} on {url}: {str(e)}", file=sys.stderr)
            continue
    
    # Take screenshot using Selenium
    screenshot_file = f"{output_dir}/screenshot_{port}.png"
    if take_webpage_screenshot(url, screenshot_file):
        results["screenshot"] = {
            "status": "success",
            "output_file": screenshot_file
        }
    
    if results:
        print(f"Web scan completed for {url} with {len(results)} results", file=sys.stderr)
    else:
        print(f"No web scan results found for {url}", file=sys.stderr)
    
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
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                try:
                    with open(f"scan_results/{target}_{port}_nuclei_web.json", "r") as f:
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
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                try:
                    with open(f"scan_results/{target}_{port}_nuclei_ssh.json", "r") as f:
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
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                try:
                    with open(f"scan_results/{target}_{port}_nuclei_dns.json", "r") as f:
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
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                try:
                    with open(f"scan_results/{target}_{port}_nuclei_snmp.json", "r") as f:
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
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                try:
                    with open(f"scan_results/{target}_{port}_nuclei_ftp.json", "r") as f:
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
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                try:
                    with open(f"scan_results/{target}_{port}_nuclei_smb.json", "r") as f:
                        results["smb"] = json.load(f)
                except json.JSONDecodeError:
                    results["smb"] = {"error": "Failed to parse Nuclei SMB output"}
        
        return results if results else {"error": "No Nuclei results found"}
        
    except subprocess.TimeoutExpired:
        return {"error": "Nuclei scan timed out"}
    except Exception as e:
        return {"error": f"Nuclei scan error: {str(e)}"}


def scan_host(
    ip: str, mac_addresses: dict[str, str], mac_vendors: dict[str, str], os_info: dict[str, str]
) -> dict:
    """
    For a given host, perform all scanning tasks concurrently.
    Tasks include port scanning, banner grabbing, HTTP header retrieval,
    SNMP probing, and SSL certificate extraction.
    """
    print(f"\nScanning host: {ip}", file=sys.stderr)
    result = {"ip": ip}
    result["mac_address"] = mac_addresses.get(ip, "N/A")
    result["mac_vendor"] = mac_vendors.get(ip, "N/A")
    result["os_info"] = os_info.get(ip, "Unknown")

    # Port scanning
    print(f"  - Port scanning {ip}...", file=sys.stderr)
    open_ports = port_scan(ip)
    result["open_ports"] = open_ports
    print(f"  - Found {len(open_ports.get('tcp', []))} open TCP ports and {len(open_ports.get('udp', []))} open UDP ports", file=sys.stderr)

    # Concurrently grab banners for all open TCP ports
    banners = {}
    tcp_ports = open_ports.get("tcp", [])
    if tcp_ports:
        print(f"  - Grabbing banners for {len(tcp_ports)} open TCP ports...", file=sys.stderr)
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
    result["banners"] = banners

    # Concurrently fetch HTTP headers for common web ports (if open)
    http_headers = {}
    web_ports = [port for port in [80, 443, 8080] if port in tcp_ports]
    if web_ports:
        print(f"  - Checking HTTP headers for {len(web_ports)} web ports...", file=sys.stderr)
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
    if web_ports:
        print(f"  - Running web scans for {len(web_ports)} web ports...", file=sys.stderr)
        web_scan_results = {}
        for port in web_ports:
            print(f"    * Scanning port {port}...", file=sys.stderr)
            results = run_web_scan(ip, port)
            if results:  # Only include if we have successful results
                web_scan_results[port] = results
        if web_scan_results:  # Only include if we have any successful results
            result["web_scan_results"] = web_scan_results

    # SNMP scanning (if SNMP port is open on UDP)
    if SNMP_PORT in open_ports.get("udp", []):
        print(f"  - Checking SNMP on port {SNMP_PORT}...", file=sys.stderr)
        result["snmp_info"] = snmp_scan(ip)
    else:
        result["snmp_info"] = "SNMP port not open"

    # Concurrently retrieve SSL certificate details for SSL-enabled ports
    ssl_certs = {}
    ssl_tcp_ports = [port for port in tcp_ports if port in SSL_PORTS]
    if ssl_tcp_ports:
        print(f"  - Checking SSL certificates for {len(ssl_tcp_ports)} SSL ports...", file=sys.stderr)
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

    print(f"  - Completed scanning {ip}", file=sys.stderr)
    return result


def cleanup_terminal():
    """Clean up any buffered output and restore terminal state."""
    try:
        # Clear any buffered output
        sys.stdout.flush()
        sys.stderr.flush()
        
        # Force a newline to ensure prompt is on a new line
        print("\n", end="", flush=True)
        
        # Restore terminal settings if they were changed
        if hasattr(cleanup_terminal, 'old_settings'):
            try:
                termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, cleanup_terminal.old_settings)
            except:
                pass
    except Exception as e:
        print(f"\nError during cleanup: {e}", file=sys.stderr, flush=True)


def signal_handler(signum, frame):
    """Handle interrupt signals gracefully."""
    print("\nInterrupt received. Cleaning up...", flush=True)
    cleanup_terminal()
    sys.exit(0)


def parse_port_list(port_string: str) -> list[int]:
    """Parse a comma-separated list of ports into integers."""
    try:
        return [int(port.strip()) for port in port_string.split(',')]
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"Invalid port number: {e}")


def check_web_tools() -> dict:
    """Check if required web scanning tools are installed."""
    available_tools = {}
    for tool, info in WEB_SCAN_TOOLS.items():
        try:
            if tool == "gobuster":
                # Gobuster doesn't support --version, use help instead
                subprocess.run([tool, "help"], capture_output=True, check=True)
                available_tools[tool] = {
                    "status": "installed",
                    "description": info["description"]
                }
            else:
                # Check if tool is installed
                subprocess.run([tool, "--version"], capture_output=True, check=True)
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


def save_results(live_hosts, port_results, web_results, snmp_results, ssl_results, os_info, vendor_info):
    """Save scan results to JSON files."""
    # Create scan_results directory
    os.makedirs("scan_results", exist_ok=True)
    
    # Save individual host results
    for ip in live_hosts:
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
    
    # Save summary results
    summary = {
        "scan_time": datetime.now().isoformat(),
        "total_hosts": len(live_hosts),
        "hosts": live_hosts,
        "os_info": os_info,
        "vendor_info": vendor_info,
        "port_results": port_results,
        "web_results": web_results,
        "snmp_results": snmp_results,
        "ssl_results": ssl_results
    }
    
    with open("scan_results/summary.json", "w") as f:
        json.dump(summary, f, indent=2)


def scan_network(network: str) -> list[str]:
    """Scan a network for live hosts."""
    try:
        # Use ping discovery to find live hosts
        live_hosts = ping_discovery(network)
        if not live_hosts:
            return []
            
        # Get MAC addresses for live hosts
        mac_addresses = resolve_mac_addresses(live_hosts)
        
        # Look up vendors for live hosts
        vendors = lookup_mac_vendors(mac_addresses)
        
        # Scan each host
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
                    print(json.dumps(result, indent=2), flush=True)
                except Exception as e:
                    print(f"Error scanning {ip}: {str(e)}", file=sys.stderr)
        
        return live_hosts
    except Exception as e:
        print(f"Error scanning network: {str(e)}", file=sys.stderr)
        return []


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


def main():
    """Main function."""
    if not is_root():
        print("Error: This script must be run as root for network scanning.")
        sys.exit(1)

    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Get network interfaces
    interfaces = get_local_ips_and_subnets()
    if not interfaces:
        print("Error: No network interfaces found.")
        sys.exit(1)

    # Print startup message
    print("\nNanitor Network Scanner")
    print("======================")
    print("Configuration:")
    print(f"- Thread count: {THREAD_COUNT}")
    print(f"- Allowed interfaces: {', '.join(ALLOWED_INTERFACES)}")
    print(f"- TCP ports to scan: {', '.join(map(str, COMMON_TCP_PORTS))}")
    print(f"- UDP ports to scan: {', '.join(map(str, COMMON_UDP_PORTS))}")
    print(f"- SSL/TLS ports: {', '.join(map(str, SSL_PORTS))}")
    print(f"- SNMP port: {SNMP_PORT}")
    print(f"- Running as root: {is_root()}")
    print(f"- OS detection: {'Enabled' if is_root() else 'Disabled (requires root)'}")
    print("\nWeb Scanning Tools:")
    for tool, info in WEB_SCAN_TOOLS.items():
        print(f"\n{tool}:")
        print(f"  Description: {info['description']}")
        print(f"  Command: {info['command']}")
        if 'features' in info:
            print("  Features:")
            for feature in info['features']:
                print(f"    - {feature}")
        if 'wordlist' in info:
            print(f"  Wordlist: {info['wordlist']}")

    print("\nFound network interfaces:")
    for interface in interfaces:
        print(f"- Interface: {interface['interface']}, IP: {interface['ip_address']}, Netmask: {interface['netmask']}")

    # Get target network
    target_network = get_target_network(interfaces)
    if not target_network:
        print("Error: No valid target network found.")
        sys.exit(1)
    print(f"\nTarget network: {target_network}\n")

    # Perform network scan
    print(f"Scanning network: {target_network}\n")
    live_hosts = scan_network(target_network)
    if not live_hosts:
        print("No live hosts found.")
        sys.exit(0)

    print(f"\nFound {len(live_hosts)} live host(s) on {target_network}.\n")

    # Resolve vendor information
    print("Resolving vendor information...")
    vendor_info = resolve_vendors(live_hosts)

    # Perform OS detection if running as root
    os_info = {}
    #if is_root():
    #    print("\nPerforming OS detection (this may take a while)...")
    #    os_info = os_fingerprinting(live_hosts)

    # Perform port scanning
    print("\nPerforming port scanning...")
    port_results = {}
    with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
        future_to_ip = {executor.submit(port_scan, ip): ip for ip in live_hosts}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                port_results[ip] = future.result()
            except Exception as e:
                print(f"    * Port scan failed for {ip}: {str(e)}", file=sys.stderr)

    # Perform web scanning
    print("\nPerforming web scanning...")
    web_results = {}
    with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
        future_to_ip = {
            executor.submit(web_scan, ip, port_results.get(ip, {}).get("tcp", [])): ip
            for ip in live_hosts
        }
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                web_results[ip] = future.result()
            except Exception as e:
                print(f"    * Web scan failed for {ip}: {str(e)}", file=sys.stderr)

    # Perform SNMP scanning
    print("\nPerforming SNMP scanning...")
    snmp_results = {}
    with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
        future_to_ip = {executor.submit(snmp_scan, ip): ip for ip in live_hosts}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                snmp_results[ip] = future.result()
            except Exception as e:
                print(f"    * SNMP scan failed for {ip}: {str(e)}", file=sys.stderr)

    # Perform SSL scanning
    print("\nPerforming SSL/TLS scanning...")
    ssl_results = {}
    with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
        future_to_ip = {
            executor.submit(ssl_scan, ip, port_results.get(ip, {}).get("tcp", [])): ip
            for ip in live_hosts
        }
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                ssl_results[ip] = future.result()
            except Exception as e:
                print(f"    * SSL scan failed for {ip}: {str(e)}", file=sys.stderr)

    # Save results
    save_results(live_hosts, port_results, web_results, snmp_results, ssl_results, os_info, vendor_info)
    print("\nScan complete! Results saved to scan_results/")


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


def snmp_scan(ip: str) -> dict:
    """Perform SNMP scanning on a target host."""
    try:
        # Common SNMP community strings to try
        communities = ['public', 'private', 'community']
        results = {
            'communities': [],
            'system_info': {},
            'interfaces': [],
            'error': None
        }
        
        for community in communities:
            try:
                # Try to get system information
                system_info = get_snmp_system_info(ip, community)
                if system_info and 'error' not in system_info:
                    results['communities'].append(community)
                    results['system_info'] = system_info
                    
                    # Try to get interface information
                    interfaces = get_snmp_interfaces(ip, community)
                    if interfaces and 'error' not in interfaces[0]:
                        results['interfaces'] = interfaces
                    
                    # If we found a working community string, we can stop
                    break
                elif system_info and 'error' in system_info:
                    print(f"    * SNMP error for {ip} with community {community}: {system_info['error']}", file=sys.stderr)
            except Exception as e:
                print(f"    * SNMP error for {ip} with community {community}: {str(e)}", file=sys.stderr)
                continue
                
        if not results['communities']:
            results['error'] = "No working SNMP community strings found"
            
        return results
    except Exception as e:
        return {'error': f'SNMP scan error: {str(e)}'}


def get_snmp_system_info(ip: str, community: str) -> dict:
    """Get system information via SNMP."""
    try:
        # System description
        system_desc = next(getCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((ip, SNMP_PORT), timeout=2, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))
        ))
        
        # System uptime
        uptime = next(getCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((ip, SNMP_PORT), timeout=2, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.3.0'))
        ))
        
        # System contact
        contact = next(getCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((ip, SNMP_PORT), timeout=2, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.4.0'))
        ))
        
        # System location
        location = next(getCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((ip, SNMP_PORT), timeout=2, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.6.0'))
        ))
        
        return {
            'description': str(system_desc[0][1]) if system_desc[0][1] else 'Unknown',
            'uptime': str(uptime[0][1]) if uptime[0][1] else 'Unknown',
            'contact': str(contact[0][1]) if contact[0][1] else 'Unknown',
            'location': str(location[0][1]) if location[0][1] else 'Unknown'
        }
    except Exception as e:
        error_msg = str(e)
        if "RequestTimedOut" in error_msg:
            return {'error': 'SNMP request timed out - device may be blocking SNMP requests'}
        elif "NoSuchObject" in error_msg:
            return {'error': 'SNMP object not found - device may not support this MIB'}
        elif "NoSuchInstance" in error_msg:
            return {'error': 'SNMP instance not found - device may not support this MIB'}
        else:
            return {'error': f'SNMP error: {error_msg}'}


def get_snmp_interfaces(ip: str, community: str) -> list:
    """Get network interface information via SNMP."""
    try:
        interfaces = []
        
        # Get interface descriptions
        if_descr = next(getCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((ip, SNMP_PORT), timeout=2, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.2'))
        ))
        
        # Get interface MAC addresses
        if_mac = next(getCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((ip, SNMP_PORT), timeout=2, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.6'))
        ))
        
        # Get interface operational status
        if_status = next(getCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((ip, SNMP_PORT), timeout=2, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.8'))
        ))
        
        # Process results
        for i in range(len(if_descr[0][1])):
            interface = {
                'description': str(if_descr[0][1][i]) if if_descr[0][1][i] else 'Unknown',
                'mac_address': str(if_mac[0][1][i]) if if_mac[0][1][i] else 'Unknown',
                'status': str(if_status[0][1][i]) if if_status[0][1][i] else 'Unknown'
            }
            interfaces.append(interface)
            
        return interfaces
    except Exception as e:
        error_msg = str(e)
        if "RequestTimedOut" in error_msg:
            return [{'error': 'SNMP request timed out - device may be blocking SNMP requests'}]
        elif "NoSuchObject" in error_msg:
            return [{'error': 'SNMP object not found - device may not support this MIB'}]
        elif "NoSuchInstance" in error_msg:
            return [{'error': 'SNMP instance not found - device may not support this MIB'}]
        else:
            return [{'error': f'SNMP error: {error_msg}'}]


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
                print(f"Error scanning SSL port {port} on {ip}: {str(e)}", file=sys.stderr)
    return results if results else "No SSL certificate info"


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
