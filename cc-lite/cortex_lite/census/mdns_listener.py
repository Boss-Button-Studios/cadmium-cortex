import logging
import socket
import time
from zeroconf import Zeroconf, ServiceBrowser, ServiceListener

# Service types to query. Covers the most common home network device classes.
QUERY_SERVICES = [
    "_workstation._tcp.local.",
    "_http._tcp.local.",
    "_hap._tcp.local.",
    "_googlecast._tcp.local.",
    "_spotify-connect._tcp.local.",
    "_smb._tcp.local.",
    "_device-info._tcp.local.",
    "_ipp._tcp.local.",
    "_homekit._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_companion-link._tcp.local.",
]


class _MDNSCollector(ServiceListener):
    """Internal listener — collects raw service info as it arrives."""

    def __init__(self):
        # Keyed by IP string → aggregated device info
        self.by_ip: dict[str, dict] = {}

    def add_service(self, zc: Zeroconf, service_type: str, name: str) -> None:
        info = zc.get_service_info(service_type, name)
        if not info:
            return
        self._ingest(info, service_type)

    def update_service(self, zc: Zeroconf, service_type: str, name: str) -> None:
        info = zc.get_service_info(service_type, name)
        if not info:
            return
        self._ingest(info, service_type)

    def remove_service(self, zc: Zeroconf, service_type: str, name: str) -> None:
        pass  # Removals are not useful for a point-in-time audit

    def _ingest(self, info, service_type: str) -> None:
        addresses = info.parsed_scoped_addresses()
        if not addresses:
            return

        # Strip the trailing ".local." from service type for readability
        svc_short = service_type.rstrip(".").replace(".local", "")

        # Decode properties — the mDNS TXT record is bytes → bytes
        properties = {}
        for k, v in info.properties.items():
            try:
                key = k.decode("utf-8") if isinstance(k, bytes) else k
                val = v.decode("utf-8") if isinstance(v, bytes) else str(v)
                properties[key] = val
            except Exception:
                pass

        # Derive the cleanest hostname available
        hostname = None
        if info.server:
            hostname = info.server.rstrip(".")
        if not hostname and info.name:
            hostname = info.name.split(".")[0]

        for ip in addresses:
            # Skip IPv6 link-local — not useful for ARP correlation
            if ":" in ip and ip.startswith("fe80"):
                continue

            if ip not in self.by_ip:
                self.by_ip[ip] = {
                    "hostname": hostname,
                    "services": [],
                    "properties": {}
                }

            entry = self.by_ip[ip]

            # Hostname: prefer the most specific one seen
            if hostname and not entry["hostname"]:
                entry["hostname"] = hostname

            if svc_short not in entry["services"]:
                entry["services"].append(svc_short)

            # Merge properties — don't overwrite existing keys
            for k, v in properties.items():
                if k not in entry["properties"]:
                    entry["properties"][k] = v


def scan(listen_seconds: int = 10) -> dict[str, dict]:
    """
    Browse all QUERY_SERVICES for `listen_seconds` and return a dict:
        { "192.168.0.x": { "hostname": ..., "services": [...], "properties": {...} } }

    Keyed by IP so callers can merge with ARP table entries by IP address.
    """
    zc = Zeroconf()
    collector = _MDNSCollector()

    browsers = [
        ServiceBrowser(zc, svc, collector)
        for svc in QUERY_SERVICES
    ]

    logging.info(f"[mDNS] Listening for {listen_seconds}s across {len(QUERY_SERVICES)} service types...")
    time.sleep(listen_seconds)

    zc.close()

    found = len(collector.by_ip)
    logging.info(f"[mDNS] Scan complete — {found} device(s) responded.")
    return collector.by_ip
