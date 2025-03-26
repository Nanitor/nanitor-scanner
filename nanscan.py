#!/usr/bin/env python3
import argparse
import json
import socket
import ssl
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_network
from typing import Dict, List

import nmap
import psutil
import requests
import scapy.all as scapy
from mac_vendor_lookup import MacLookup
from ping3 import ping
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
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ----------------------- Configuration -----------------------
ALLOWED_INTERFACES = ["eth0", "wlan0", "en0"]
THREAD_COUNT = 10

# Ports often exploited by attackers
COMMON_TCP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 3389, 8080, 8443]
COMMON_UDP_PORTS = [53, 67, 69, 123, 161, 162, 500, 514, 520, 33434]
SNMP_PORT = 161

# Ports that typically speak SSL/TLS
SSL_PORTS = [443, 8443]
# ----------------------- End Configuration -------------------


def get_local_ips_and_subnets() -> List[Dict[str, str]]:
    """
    Retrieve all local IP addresses and netmasks for allowed interfaces.
    """
    ip_info = []
    for interface, addrs in psutil.net_if_addrs().items():
        if interface not in ALLOWED_INTERFACES:
            continue
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ip_info.append({
                    "interface": interface,
                    "ip_address": addr.address,
                    "netmask": addr.netmask
                })
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


def ping_discovery(network: str) -> List[str]:
    """
    Discover live hosts on the given network range via parallel pinging.
    """
    net = ip_network(network, strict=False)
    with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
        results = list(executor.map(ping_host, [str(ip) for ip in net.hosts()]))
    return [ip for ip in results if ip]


def get_arp_table() -> Dict[str, str]:
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


def resolve_mac_addresses(live_hosts: List[str]) -> Dict[str, str]:
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
            for sent, received in answered:
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


def lookup_mac_vendors(mac_addresses: Dict[str, str]) -> Dict[str, str]:
    """
    Perform MAC vendor lookups concurrently.
    """
    with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
        results = list(executor.map(lookup_mac_vendor, mac_addresses.values()))
    return dict(zip(mac_addresses.keys(), results))


def os_fingerprint(ip: str) -> Dict[str, str]:
    """
    Perform OS fingerprinting on a single host using Nmap.
    """
    nm = nmap.PortScanner()
    try:
        scan_data = nm.scan(ip, arguments='-O')
        osmatches = scan_data.get('scan', {}).get(ip, {}).get('osmatch', [])
        if osmatches:
            os_name = osmatches[0].get('name', 'Unknown')
        else:
            os_name = 'Unknown'
        return {ip: os_name}
    except Exception as e:
        return {ip: f"Error: {e}"}


def os_fingerprinting(ip_addresses: List[str]) -> Dict[str, str]:
    """
    Perform OS fingerprinting on multiple hosts concurrently.
    """
    os_info = {}
    with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
        results = list(executor.map(os_fingerprint, ip_addresses))
    for result in results:
        os_info.update(result)
    return os_info


def port_scan(ip: str) -> Dict[str, List[int]]:
    """
    Scan for open TCP and UDP ports on a given host.
    """
    nm = nmap.PortScanner()
    open_ports = {"tcp": [], "udp": []}
    try:
        # TCP Scan
        nm.scan(hosts=ip, arguments=f'-p {",".join(map(str, COMMON_TCP_PORTS))} -sT')
        if ip in nm.all_hosts() and "tcp" in nm[ip]:
            open_ports["tcp"] = [int(port) for port, info in nm[ip]["tcp"].items() if info["state"] == "open"]

        # UDP Scan
        nm.scan(hosts=ip, arguments=f'-p {",".join(map(str, COMMON_UDP_PORTS))} -sU')
        if ip in nm.all_hosts() and "udp" in nm[ip]:
            open_ports["udp"] = [int(port) for port, info in nm[ip]["udp"].items() if info["state"] == "open"]
    except Exception as e:
        open_ports["error"] = str(e)
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


def get_http_headers(ip: str, port: int) -> Dict[str, str]:
    """
    Retrieve HTTP headers from a service running on the given IP and port.
    """
    try:
        url = f"https://{ip}:{port}" if port == 443 else f"http://{ip}:{port}"
        response = requests.head(url, timeout=2, verify=False)
        return dict(response.headers)
    except Exception:
        return {}


def snmp_scan(ip: str) -> Dict[str, str]:
    """
    Perform SNMP queries on the given IP for common OIDs.
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
                    CommunityData('public', mpModel=0),
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
    return snmp_data


def get_ssl_certificate(ip: str, port: int = 443) -> Dict:
    """
    Retrieve SSL certificate details from the given IP and port.
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((ip, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        return {"error": str(e)}


def scan_host(ip: str, mac_addresses: Dict[str, str],
              mac_vendors: Dict[str, str],
              os_info: Dict[str, str]) -> Dict:
    """
    For a given host, perform all scanning tasks concurrently.
    Tasks include port scanning, banner grabbing, HTTP header retrieval,
    SNMP probing, and SSL certificate extraction.
    """
    result = {"ip": ip}
    result["mac_address"] = mac_addresses.get(ip, "N/A")
    result["mac_vendor"] = mac_vendors.get(ip, "N/A")
    result["os_info"] = os_info.get(ip, "Unknown")

    # Port scanning
    open_ports = port_scan(ip)
    result["open_ports"] = open_ports

    # Concurrently grab banners for all open TCP ports
    banners = {}
    tcp_ports = open_ports.get("tcp", [])
    if tcp_ports:
        with ThreadPoolExecutor(max_workers=len(tcp_ports)) as banner_executor:
            future_to_port = {banner_executor.submit(get_banner, ip, port): port for port in tcp_ports}
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
        with ThreadPoolExecutor(max_workers=len(web_ports)) as http_executor:
            future_to_port = {http_executor.submit(get_http_headers, ip, port): port for port in web_ports}
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    http_headers[port] = future.result()
                except Exception:
                    http_headers[port] = {}
    result["http_headers"] = http_headers

    # SNMP scanning (if SNMP port is open on UDP)
    if SNMP_PORT in open_ports.get("udp", []):
        result["snmp_info"] = snmp_scan(ip)
    else:
        result["snmp_info"] = "SNMP port not open"

    # Concurrently retrieve SSL certificate details for SSL-enabled ports
    ssl_certs = {}
    ssl_tcp_ports = [port for port in tcp_ports if port in SSL_PORTS]
    if ssl_tcp_ports:
        with ThreadPoolExecutor(max_workers=len(ssl_tcp_ports)) as ssl_executor:
            future_to_port = {ssl_executor.submit(get_ssl_certificate, ip, port): port for port in ssl_tcp_ports}
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    ssl_certs[port] = future.result()
                except Exception as e:
                    ssl_certs[port] = {"error": str(e)}
    result["ssl_certificates"] = ssl_certs if ssl_certs else "No SSL certificate info"

    return result


def main():
    try:
        # Get local network information
        ip_info = get_local_ips_and_subnets()
        if not ip_info:
            print("Error: No suitable network interfaces found. Please check your network connection.")
            return 1

        for info in ip_info:
            network = calculate_network(info["ip_address"], info["netmask"])
            print(f"\nScanning network: {network}")
            
            try:
                # Find live hosts
                live_hosts = ping_discovery(network)
                if not live_hosts:
                    print("No live hosts found on this network.")
                    continue
                
                print(f"Found {len(live_hosts)} live host(s) on {network}.")
                
                try:
                    # Get MAC addresses
                    mac_addresses = resolve_mac_addresses(live_hosts)
                    if mac_addresses:
                        print("Resolving vendor information...")
                        vendors = lookup_mac_vendors(mac_addresses)
                except Exception as e:
                    print("Warning: Could not resolve MAC addresses or vendor information.")
                    print(f"Reason: {str(e)}")
                
                try:
                    # OS fingerprinting
                    print("Performing OS detection...")
                    os_info = os_fingerprinting(live_hosts)
                except Exception as e:
                    print("Warning: OS detection failed.")
                    print(f"Reason: {str(e)}")
                
                # Concurrently scan each live host
                with ThreadPoolExecutor(max_workers=THREAD_COUNT) as host_executor:
                    future_to_ip = {
                        host_executor.submit(scan_host, ip, mac_addresses, vendors, os_info): ip
                        for ip in live_hosts
                    }
                    for future in as_completed(future_to_ip):
                        ip = future_to_ip[future]
                        try:
                            scan_result = future.result()
                        except Exception as e:
                            scan_result = {"ip": ip, "error": str(e)}
                        print(json.dumps(scan_result, indent=4))
                
            except Exception as e:
                print(f"Error while scanning network {network}")
                print(f"Reason: {str(e)}")
                continue

    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        return 1
    except Exception as e:
        print("\nError: An unexpected error occurred.")
        print(f"Details: {str(e)}")
        print("\nIf this problem persists, please check:")
        print("- Your network connection")
        print("- System permissions")
        print("- Available system resources")
        return 1

    return 0


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
