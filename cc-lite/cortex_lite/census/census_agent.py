"""
census_agent.py
===============
Deterministic device dossier builder for CC-Lite.

Takes raw ARP entries, mDNS data, and OUI lookup results and produces
a structured dossier for each observed device. Classification is done
entirely in code — the LLM never sees unclassified devices.

Device classes (in priority order):
  Infrastructure — gateway, WAPs, switches, routers. Never a finding target.
  Admin          — the administrator's device. Never a finding target.
  IoT            — smart home devices, cameras, appliances. Article IV scope.
  Unknown-Random — locally administered (randomized) MAC. Article III, low only.
  Unknown        — unresolvable OUI, no disambiguating signals. Article III.
  Private        — laptops, workstations, NAS. Not a finding target
                   in passive observation mode (no Sheriff, no Article II trigger).

Vendor classification rationale:
  Vendors like Apple, Samsung, Google, and Amazon are classified as IoT at
  medium confidence when their OUI is observed. This is because modern phones
  and tablets from these vendors almost universally use MAC randomization —
  a real OUI sighting is more likely a smart appliance, TV, or hub than a
  personal device. PC and chipset manufacturers (Dell, Intel, Lenovo, etc.)
  don't make consumer IoT and stay in _PRIVATE_VENDORS.

CC-Lite valid article scope: III and IV only.
Articles I and II require active enforcement context (Sheriff) and cannot be
triggered by passive observation. They are excluded at the architecture level.
"""

import logging
from dataclasses import dataclass, field, asdict
from typing import Optional

# ---------------------------------------------------------------------------
# Vendor classification lists
# ---------------------------------------------------------------------------

# OUI vendor substrings that strongly indicate networking infrastructure
_INFRA_VENDORS = {
    "synology", "tp-link", "netgear", "cisco", "ubiquiti", "linksys",
    "d-link", "zyxel", "aruba", "juniper", "extreme networks", "nokia",
    "ericsson", "huawei", "mikrotik", "peplink", "cambium", "ruckus",
    "fortinet", "palo alto", "sonicwall", "watchguard",
}

# OUI vendor substrings that strongly indicate IoT / embedded devices.
#
# High-confidence IoT: purpose-built embedded/smart home vendors
_IOT_VENDORS_HIGH = {
    "espressif", "tuya", "ecobee", "nest", "wemo", "ring", "belkin",
    "lifx", "sengled", "lutron", "sonos", "august", "qingdao", "shenzhen",
    "ge appliances", "azurewave", "silicon laboratories",
    "texas instruments", "nordic semiconductor", "particle industries",
}

# Medium-confidence IoT: major consumer brands whose OUI sightings are more
# likely appliances/TVs than phones, because phones from these vendors
# use MAC randomization by default on modern OS versions.
#   Apple    — randomizes since iOS 14 / macOS 12; OUI = likely Apple TV / HomePod
#   Samsung  — randomizes on Android 10+; OUI = likely TV / refrigerator / appliance
#   Google   — Pixels randomize; OUI = likely Nest / Chromecast
#   Amazon   — OUI = almost certainly Echo / Fire device
_IOT_VENDORS_MEDIUM = {
    "apple", "samsung", "google", "amazon",
}

# Combined set for lookup convenience
_IOT_VENDORS = _IOT_VENDORS_HIGH | _IOT_VENDORS_MEDIUM

# OUI vendor substrings that indicate personal / workstation / infrastructure
# components. These vendors do not make consumer IoT devices.
_PRIVATE_VENDORS = {
    "microsoft", "lenovo", "dell", "hp inc", "hewlett packard",
    "intel", "realtek", "broadcom", "qualcomm", "murata",
}

# mDNS service types that indicate IoT devices
_IOT_SERVICES = {
    "_hap._tcp",            # HomeKit
    "_homekit._tcp",
    "_googlecast._tcp",     # Chromecast / Google Home
    "_airplay._tcp",        # AirPlay speakers / TVs
    "_raop._tcp",           # AirPlay audio
    "_spotify-connect._tcp",
}

# mDNS service types that indicate personal / workstation devices
_PRIVATE_SERVICES = {
    "_workstation._tcp",
    "_smb._tcp",
    "_companion-link._tcp",  # iOS/macOS continuity
}

# Hostname substrings that suggest network infrastructure
_INFRA_HOSTNAMES = {
    "router", "gateway", "switch", "wap", "-ap-", "access-point",
    "synologyrouter", "rt", "orbi", "eero", "mesh",
}


# ---------------------------------------------------------------------------
# Dossier dataclass
# ---------------------------------------------------------------------------

@dataclass
class DeviceDossier:
    # Identity
    device_id: str                        # hex MAC, no colons
    mac: str                              # colon-separated MAC
    ip: str
    arp_state: str                        # REACHABLE, DELAY, etc.

    # OUI
    oui_vendor: str = "Unknown"
    oui_confidence: str = "unknown"       # high / medium / low / unknown / none
    locally_administered: bool = False

    # mDNS
    hostname: Optional[str] = None
    mdns_services: list = field(default_factory=list)
    mdns_properties: dict = field(default_factory=dict)

    # Router label (optional — populated when known_devices.csv is present)
    router_label: Optional[str] = None
    label_source: Optional[str] = None   # "router_export" | "manual" | None

    # Classification (set by classify())
    device_class: str = "Unknown"         # Infrastructure/Admin/IoT/Unknown-Random/Unknown/Private
    class_confidence: str = "low"         # high / medium / low / none
    class_basis: list = field(default_factory=list)  # signals that drove the decision

    # Flags
    is_admin: bool = False
    is_gateway: bool = False
    oui_label_mismatch: bool = False      # OUI vendor contradicts router label

    def to_dict(self) -> dict:
        return asdict(self)

    def to_audit_dict(self) -> dict:
        """
        Trimmed representation for LLM prompt injection.
        Omits debug fields (class_basis, mdns_properties, label_source)
        that are useful for logging but add prompt tokens without helping
        the auditor reason.
        """
        return {
            "device_id":          self.device_id,
            "ip":                 self.ip,
            "oui_vendor":         self.oui_vendor,
            "oui_confidence":     self.oui_confidence,
            "locally_administered": self.locally_administered,
            "hostname":           self.hostname,
            "mdns_services":      self.mdns_services,
            "router_label":       self.router_label,
            "device_class":       self.device_class,
            "class_confidence":   self.class_confidence,
            "oui_label_mismatch": self.oui_label_mismatch,
        }


# ---------------------------------------------------------------------------
# Classification engine
# ---------------------------------------------------------------------------

def _vendor_matches(vendor: str, keyword_set: set) -> bool:
    v = vendor.lower()
    return any(k in v for k in keyword_set)


def _hostname_matches(hostname: Optional[str], keyword_set: set) -> bool:
    if not hostname:
        return False
    h = hostname.lower()
    return any(k in h for k in keyword_set)


def _classify(dossier: DeviceDossier, admin_mac: str, gateway_ip: str) -> None:
    """
    Populate device_class, class_confidence, class_basis, is_admin,
    is_gateway, and oui_label_mismatch in place.

    Priority order: Admin > Infrastructure > IoT > Private > Unknown-Random > Unknown
    """
    basis = []

    # --- Admin ---
    clean_admin = admin_mac.lower().replace(":", "").replace("-", "")
    if dossier.device_id.lower() == clean_admin:
        dossier.device_class     = "Admin"
        dossier.class_confidence = "high"
        dossier.class_basis      = ["admin_mac_match"]
        dossier.is_admin         = True
        return

    # --- Gateway / Infrastructure by IP ---
    if dossier.ip == gateway_ip:
        dossier.device_class     = "Infrastructure"
        dossier.class_confidence = "high"
        dossier.class_basis      = ["gateway_ip_match"]
        dossier.is_gateway       = True
        return

    # --- Locally administered (randomized MAC) ---
    # Classified before vendor checks — OUI is meaningless for these
    if dossier.locally_administered:
        dossier.device_class     = "Unknown-Random"
        dossier.class_confidence = "none"
        dossier.class_basis      = ["locally_administered_mac"]
        return

    # --- Infrastructure by vendor or hostname ---
    if _vendor_matches(dossier.oui_vendor, _INFRA_VENDORS):
        basis.append("oui_vendor_infra")
    if _hostname_matches(dossier.hostname, _INFRA_HOSTNAMES):
        basis.append("hostname_infra")
    if dossier.router_label and any(
        k in dossier.router_label.lower() for k in _INFRA_HOSTNAMES
    ):
        basis.append("router_label_infra")

    if basis:
        dossier.device_class     = "Infrastructure"
        dossier.class_confidence = "high" if len(basis) > 1 else "medium"
        dossier.class_basis      = basis
        return

    # --- IoT by vendor ---
    if _vendor_matches(dossier.oui_vendor, _IOT_VENDORS_HIGH):
        basis.append("oui_vendor_iot_high")
    elif _vendor_matches(dossier.oui_vendor, _IOT_VENDORS_MEDIUM):
        basis.append("oui_vendor_iot_medium")

    # --- IoT by mDNS services ---
    iot_services_seen = [s for s in dossier.mdns_services if s in _IOT_SERVICES]
    if iot_services_seen:
        basis.append(f"mdns_services:{','.join(iot_services_seen)}")

    if basis:
        dossier.device_class = "IoT"
        # High confidence if high-confidence vendor OR mDNS corroborates medium vendor
        if "oui_vendor_iot_high" in basis or (
            "oui_vendor_iot_medium" in basis and len(basis) > 1
        ):
            dossier.class_confidence = "high"
        else:
            dossier.class_confidence = "medium"
        dossier.class_basis = basis
        _check_label_mismatch(dossier)
        return

    # --- Private by vendor or mDNS ---
    if _vendor_matches(dossier.oui_vendor, _PRIVATE_VENDORS):
        basis.append("oui_vendor_private")

    private_services_seen = [s for s in dossier.mdns_services if s in _PRIVATE_SERVICES]
    if private_services_seen:
        basis.append(f"mdns_services:{','.join(private_services_seen)}")

    if basis:
        dossier.device_class     = "Private"
        dossier.class_confidence = "medium"
        dossier.class_basis      = basis
        _check_label_mismatch(dossier)
        return

    # --- Unknown OUI, no disambiguating signals ---
    dossier.device_class     = "Unknown"
    dossier.class_confidence = "low"
    dossier.class_basis      = ["no_identifying_signals"]


def _check_label_mismatch(dossier: DeviceDossier) -> None:
    """
    Flag cases where the router label contradicts the OUI-based classification.
    Example: OUI says Apple but label says 'Linux_Node'.
    """
    if not dossier.router_label:
        return

    label_lower  = dossier.router_label.lower()
    vendor_lower = dossier.oui_vendor.lower()

    if "apple" in vendor_lower and any(
        k in label_lower for k in ["linux", "android", "windows"]
    ):
        dossier.oui_label_mismatch = True
    elif "samsung" in vendor_lower and "apple" in label_lower:
        dossier.oui_label_mismatch = True


# ---------------------------------------------------------------------------
# Optional router label loader
# ---------------------------------------------------------------------------

def load_router_labels(csv_path: str) -> dict:
    """
    Load a router-exported device label CSV.
    Expected format: mac,label  (header optional)
    Returns dict keyed by normalised MAC hex (no colons, lowercase).
    """
    import csv, os
    labels = {}
    if not os.path.exists(csv_path):
        return labels
    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) < 2:
                    continue
                mac   = row[0].strip().lower().replace(":", "").replace("-", "")
                label = row[1].strip()
                if mac and label and mac != "mac":  # skip header if present
                    labels[mac] = label
        logging.info(f"Loaded {len(labels)} router labels from {csv_path}")
    except Exception as e:
        logging.error(f"Failed to load router labels from {csv_path}: {e}")
    return labels


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def build_dossiers(
    arp_entries: list,
    mdns_data: dict,
    oui_lookup,
    admin_mac: str,
    gateway_ip: str,
    router_labels: Optional[dict] = None,
) -> list:
    """
    Build a dossier for every live ARP entry.

    Parameters
    ----------
    arp_entries   : list of dicts from arp_reader.get_arp_table()
    mdns_data     : dict keyed by IP from mdns_listener.scan()
    oui_lookup    : OUILookup instance
    admin_mac     : admin MAC from CONFIG
    gateway_ip    : gateway IP from CONFIG
    router_labels : optional dict from load_router_labels()

    Returns list of DeviceDossier, one per ARP entry.
    """
    dossiers = []

    for entry in arp_entries:
        mac = entry.get("mac", "")
        if not mac:
            logging.warning(f"Skipping ARP entry with no MAC: {entry}")
            continue

        device_id = mac.replace(":", "").lower()
        ip        = entry.get("ip", "")
        state     = entry.get("state", "UNKNOWN")

        # OUI lookup
        vendor, confidence = oui_lookup.lookup(mac)

        # Locally administered flag
        first_octet          = int(device_id[:2], 16)
        locally_administered = bool(first_octet & 0x02)

        # mDNS enrichment
        mdns_info  = mdns_data.get(ip, {})
        hostname   = mdns_info.get("hostname")
        services   = mdns_info.get("services", [])
        properties = mdns_info.get("properties", {})

        # Router label enrichment
        router_label = None
        label_source = None
        if router_labels:
            router_label = router_labels.get(device_id)
            if router_label:
                label_source = "router_export"

        dossier = DeviceDossier(
            device_id            = device_id,
            mac                  = mac,
            ip                   = ip,
            arp_state            = state,
            oui_vendor           = vendor,
            oui_confidence       = confidence,
            locally_administered = locally_administered,
            hostname             = hostname,
            mdns_services        = services,
            mdns_properties      = properties,
            router_label         = router_label,
            label_source         = label_source,
        )

        _classify(dossier, admin_mac, gateway_ip)
        dossiers.append(dossier)

    class_counts = {}
    for d in dossiers:
        class_counts[d.device_class] = class_counts.get(d.device_class, 0) + 1

    logging.info(
        f"Census complete: {len(dossiers)} devices — "
        + ", ".join(
            f"{cls}: {class_counts[cls]}"
            for cls in ["Infrastructure", "Admin", "IoT",
                        "Unknown-Random", "Unknown", "Private"]
            if cls in class_counts
        )
    )

    return dossiers
