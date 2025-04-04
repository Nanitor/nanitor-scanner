#!/usr/bin/env python3
import os
import json
import requests
import argparse
from typing import Any
from models import DiscoveredHost  # Shared type definition


def convert_scan_results_to_nanitor_import(
    live_hosts: list[DiscoveredHost],
    scan_results: dict[str, Any],
    organization_id: int = None,
    source_name: str = "nanitor-scanner",
    source_type: str = "api",
    suppress_events: bool = False,
) -> dict[str, Any]:
    """
    Convert scanner results into Nanitor's DeviceImportForm JSON format.

    This function maps each discovered host into an asset entry conforming to the
    ImportDeviceEntry schema. It also maps OS data into an ImportOperatingSystemItem and
    formats vulnerabilities as ImportVulnerabilityItem objects.

    Args:
      live_hosts: List of DiscoveredHost objects.
      scan_results: Dictionary containing scan results with keys such as:
                    - vendor_info
                    - os_info
                    - port_results
                    - web_results
                    - snmp_results
                    - ssl_results
      organization_id: Organization ID to import assets into.
      source_name: Name of the source.
      source_type: Type of source.
      suppress_events: Whether to suppress events during import.

    Returns:
      A dictionary formatted per Nanitor's API import payload.
    """
    assets = []
    vendor_info = scan_results.get("vendor_info", {})
    os_info = scan_results.get("os_info", {})
    port_results = scan_results.get("port_results", {})
    web_results = scan_results.get("web_results", {})
    snmp_results = scan_results.get("snmp_results", {})
    ssl_results = scan_results.get("ssl_results", {})
    mdns_results = scan_results.get("mdns_results", {})

    for host in live_hosts:
        ip = host.ip
        hostname = host.hostnames[0] if host.hostnames else ip
        fqdn = hostname if "." in hostname else None
        web_host_results = web_results.get(ip, {})

        # Collect additional scan details into metadata.
        metadata = {
            "os_fingerprint": os_info.get(ip, "Unable to determine"),
            "open_ports": port_results.get(ip, {}),
            "web_scan_results": web_host_results,
            "snmp_info": snmp_results.get(ip, "SNMP not scanned or port closed"),
            "ssl_certificates": ssl_results.get(ip, "No SSL certificate info"),
            "reverse_dns_hostnames": [host.hostnames] if host.hostnames else [],
            "mdns_info": mdns_results.get(ip, "No mdns info available"),
        }
        # Clean up any non-safe characters in the metadata prior to import.
        metadata = recursively_escape_strings(metadata)

        # Build the asset entry conforming to ImportDeviceEntry.
        asset = {
            "hostname": hostname,
            "fqdn": fqdn,
            "ip_address": [ip],
            "labels": ["imported", "scanner"],
            "manufacturer": vendor_info.get(ip, "Unknown"),
            "metadata": metadata,
        }
        assets.append(asset)

    import_payload = {"assets": assets, "organization_id": organization_id, "source_name": source_name, "source_type": source_type, "suppress_events": suppress_events}
    return import_payload


def escape_string(s: str) -> str:
    if not isinstance(s, str):
        return s
    return s.encode("unicode_escape").decode("ascii")


def recursively_escape_strings(data):
    if isinstance(data, dict):
        return {k: recursively_escape_strings(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [recursively_escape_strings(item) for item in data]
    elif isinstance(data, str):
        return escape_string(data)
    else:
        return data


def send_to_nanitor_api(import_data: dict[str, Any]) -> Any:
    """
    Send the import JSON data to Nanitor's API.

    Expects the following environment variable to be set:
      - NANITOR_API_URL: The base URL of your Nanitor API (e.g. https://my.nanitor.net/system_api)
      - NANITOR_API_KEY: The API key with write permission.

    Returns:
      The parsed JSON response if successful.
    """
    base_url = os.getenv("NANITOR_API_URL")
    api_key = os.getenv("NANITOR_API_KEY")

    if not base_url or not api_key:
        raise ValueError("Missing required environment variables. Please set NANITOR_API_URL (e.g. https://my.nanitor.net/system_api) and NANITOR_API_KEY.")

    url = f"{base_url}/assets/import"
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}

    response = requests.post(url, headers=headers, json=import_data)
    if response.status_code == 200:
        return response.json()
    else:
        response.raise_for_status()


def main():
    parser = argparse.ArgumentParser(
        description="Nanitor API Import Tool - Import scan results in Nanitor JSON format.", epilog="Example usage: python api.py import nanitor_import.json --org-id 5"
    )
    parser.add_argument("command", choices=["import"], help="Command to execute. Currently only supports 'import'.")
    parser.add_argument("file", help="Path to the JSON file to import (e.g. nanitor_import.json).")
    parser.add_argument("--org-id", type=int, required=True, help="Organization ID to import assets into.")
    args = parser.parse_args()

    # Check for required environment variables.
    base_url = os.getenv("NANITOR_API_URL")
    api_key = os.getenv("NANITOR_API_KEY")
    if not base_url or not api_key:
        print(
            "Error: Missing required environment variables.\n"
            "Please set the following:\n"
            "  - NANITOR_API_URL: e.g. https://my.nanitor.net/system_api\n"
            "  - NANITOR_API_KEY: Your API key with write permissions."
        )
        exit(1)

    # Read the JSON file containing the Nanitor import payload.
    try:
        with open(args.file) as f:
            import_data = json.load(f)
    except Exception as e:
        print(f"Error reading file {args.file}: {e}")
        exit(1)

    # Set or override the organization ID in the payload.
    import_data["organization_id"] = args.org_id

    # For debugging:
    # print(json.dumps(import_data, indent=4))

    try:
        response = send_to_nanitor_api(import_data)
        print("Import successful! API response:")
        print(json.dumps(response, indent=4))
    except Exception as e:
        print("Import failed:", str(e))
        exit(1)


if __name__ == "__main__":
    main()
