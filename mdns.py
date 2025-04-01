# mdns.py
import threading
import time

from zeroconf import ServiceBrowser, Zeroconf


class MDNSListener:
    def __init__(self):
        self.services = {}

    def add_service(self, zeroconf, service_type, name):
        # Check if we're dealing with the meta-service.
        if service_type.lower() == "_services._dns-sd._udp.local.":
            # Store the service name with minimal info.
            self.services[name] = {
                "type": service_type,
                "name": name,
                "addresses": [],
                "port": None,
                "properties": {}
            }
            print(f"[mDNS] Discovered meta service: {name}")
            return

        # For standard services, fetch details.
        info = zeroconf.get_service_info(service_type, name)
        if not info:
            return

        addresses = info.parsed_addresses()

        # Recursively decode any bytes in the properties
        decoded_props = decode_bytes(info.properties)

        self.services[name] = {
            "type": service_type,
            "name": name,
            "addresses": addresses,
            "port": info.port,
            "properties": decoded_props
        }
        if addresses:
            print(f"[mDNS] Discovered service: {name} ({service_type}) at {addresses[0]}:{info.port}")
        else:
            print(f"[mDNS] Discovered service: {name} ({service_type}), but no addresses found.")

    def update_service(self, zeroconf, service_type, name):
        # For now, we don't need to update services; stub implementation.
        pass

    def remove_service(self, zeroconf, service_type, name):
        if name in self.services:
            print(f"[mDNS] Service removed: {name}")
            del self.services[name]


class MDNSDiscovery:
    def __init__(self, service_types=None):
        self.zeroconf = Zeroconf()
        self.listener = MDNSListener()

         # If no service types are provided, default to a couple of typical ones.
        if service_types is None:
            self.service_types = ['_http._tcp.local.', '_workstation._tcp.local.']
        else:
            self.service_types = service_types

        self.browsers = []

    def start(self):
        for stype in self.service_types:
            self.browsers.append(ServiceBrowser(self.zeroconf, stype, self.listener))

    def stop(self):
        self.zeroconf.close()

    def get_services(self):
        return self.listener.services


def run_mdns_discovery_until(stop_event: threading.Event, min_duration=10, service_types=None):
    """
    Run mDNS discovery until stop_event is set, ensuring it runs at least min_duration seconds.
    
    TWO-PHASE logic if service_types is None:
      Phase 1: Query meta-service (_services._dns-sd._udp.local.) to discover available service types.
               Runs for half of min_duration (or until stop_event).
      Phase 2: For each discovered service type, gather detailed info.
               Runs for the remaining time (or until stop_event).
    
    SINGLE-PHASE if service_types is not None:
      Just query those service types once, for min_duration or until stop_event.

    Returns a dictionary of discovered services (JSON-serializable).
    """

    start_time = time.time()

    if service_types is None:
        # ---------------- Phase 1: Meta-service ----------------
        print("[mDNS] PHASE 1: Querying meta-service (_services._dns-sd._udp.local.)")
        half_duration = min_duration / 2

        meta_disc = MDNSDiscovery(service_types=['_services._dns-sd._udp.local.'])
        meta_disc.start()

        while (time.time() - start_time) < half_duration and not stop_event.is_set():
            time.sleep(0.5)

        meta_disc.stop()
        meta_services = meta_disc.get_services()

        # Extract discovered service types from meta-services
        discovered_types = []
        for svc_name, svc_data in meta_services.items():
            if svc_data["type"].lower() == "_services._dns-sd._udp.local.":
                # The instance name is the actual service type
                # e.g. "_http._tcp.local.", etc.
                if svc_name.lower() != "_services._dns-sd._udp.local.":
                    discovered_types.append(svc_name)

        print(f"[mDNS] PHASE 1 complete. Found service types: {discovered_types}")

        if not discovered_types:
            print("[mDNS] No service types discovered. Returning meta-service data only.")
            return meta_services

        # ---------------- Phase 2: Discovered service types ----------------
        print("[mDNS] PHASE 2: Querying discovered service types for detailed info...")
        detail_disc = MDNSDiscovery(service_types=discovered_types)
        detail_disc.start()

        while (time.time() - start_time) < min_duration and not stop_event.is_set():
            time.sleep(0.5)

        detail_disc.stop()
        detail_services = detail_disc.get_services()

        # Combine meta and detail
        combined = dict(meta_services)
        combined.update(detail_services)

        print("[mDNS] PHASE 2 complete. Discovery finished.")
        return combined

    else:
        # SINGLE-PHASE with given service types
        print("[mDNS] Single-phase discovery for provided service types.")
        disc = MDNSDiscovery(service_types)
        disc.start()
        while (time.time() - start_time) < min_duration and not stop_event.is_set():
            time.sleep(0.5)
        disc.stop()
        discovered = disc.get_services()
        return discovered


def run_mdns_in_background(min_duration=10, service_types=None):
    """
    Run mDNS discovery in a background thread until signaled to stop.

    - If service_types is None, uses the two-phase approach (meta-service first,
      then discovered types).  (Like broadcast-dns-service-discovery.)
    - Otherwise, single-phase for the given service_types.

    Returns:
      (stop_event, services_container)
        stop_event: threading.Event used to stop discovery early
        services_container: a dictionary that will be filled with discovered services
                            once discovery completes
    """
    stop_event = threading.Event()
    services_container = {}

    def discovery_task():
        results = run_mdns_discovery_until(stop_event, min_duration, service_types)
        services_container.update(results)

    t = threading.Thread(target=discovery_task, daemon=True)
    t.start()
    return stop_event, services_container

def decode_bytes(obj):
    """
    Recursively decode bytes in dictionaries, lists, or individual values into UTF-8 strings.
    """
    if isinstance(obj, dict):
        decoded = {}
        for key, value in obj.items():
            # Decode key if it's bytes
            if isinstance(key, bytes):
                key = key.decode("utf-8", errors="replace")
            decoded[decode_bytes(key)] = decode_bytes(value)
        return decoded
    elif isinstance(obj, list):
        return [decode_bytes(item) for item in obj]
    elif isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    else:
        return obj


def add_mdns_results_to_host(mdns_results, single_host):
    """
    Integrate mDNS discovery results into a single host dictionary.

    Args:
        mdns_results (dict): The overall mDNS results from your scanner
        single_host (dict): A single host dictionary with at least 'ip'

    Returns:
        dict: The updated single_host dict, now with a 'mdns' key if services match
    """
    # Ensure there's a 'mdns' field
    single_host["mdns"] = []

    # This host's IP
    host_ip = single_host["ip"]

    # Go through each service in the mDNS results
    for service_name, service_info in mdns_results.items():
        addresses = service_info.get("addresses", [])
        # If the host IP is in this service's addresses, attach the info
        if host_ip in addresses:
            single_host["mdns"].append({
                "name": service_name,
                "type": service_info["type"],
                "port": service_info["port"],
                "properties": service_info["properties"],
            })

    return single_host


def map_mdns_results_by_ip(mdns_services: dict) -> dict:
    """
    Convert mDNS results from a service-keyed dictionary to a mapping of host IPs to a list of mDNS entries.

    Args:
        mdns_services: A dictionary where keys are service names and values are dicts containing mDNS info,
                       including an 'addresses' key (a list of IPs).
                       
    Returns:
        A dictionary mapping host IPs to lists of mDNS result dicts.
    """
    mapping = {}
    for service_name, service_info in mdns_services.items():
        addresses = service_info.get("addresses", [])
        # Optionally, you might want to include the service name in the info.
        service_entry = service_info.copy()
        service_entry["service_name"] = service_name
        for ip in addresses:
            mapping.setdefault(ip, []).append(service_entry)
    return mapping
