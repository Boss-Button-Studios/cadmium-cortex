import subprocess
import re
import logging

# States from `ip neigh show` that indicate the device is likely still present.
# REACHABLE: confirmed reachable within the last reachable timeout
# DELAY:     recently used, confirmation pending — still live
# PROBE:     actively being confirmed — still live
# PERMANENT: statically configured
# Excluded: STALE, FAILED, INCOMPLETE, NOARP
LIVE_STATES = {"REACHABLE", "DELAY", "PROBE", "PERMANENT"}


def get_arp_table(interface: str = "wlp3s0") -> list[dict]:
    """
    Returns a list of live ARP entries as dicts with keys:
        mac, ip, interface, state

    Uses `ip neigh show` as the primary method — it exposes neighbour state
    so stale entries can be filtered out before the auditor sees them.
    Falls back to `arp -a` if iproute2 is unavailable, with a warning that
    state filtering is not possible in that mode.
    """
    devices = _from_ip_neigh(interface)
    if devices is not None:
        return devices

    logging.warning(
        "'ip neigh' unavailable — falling back to 'arp -a'. "
        "Stale ARP entries cannot be filtered in this mode."
    )
    devices = _from_arp_a()
    return devices if devices is not None else []


def _from_ip_neigh(interface: str) -> list[dict] | None:
    """
    Parse `ip neigh show` output.
    Returns None if the command is unavailable so the caller can fall back.

    Example line:
        192.168.0.1 dev wlp3s0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
    """
    try:
        result = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True, text=True, check=True
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None

    devices = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if "lladdr" not in parts:
            continue

        # State is the last token; default to STALE if absent
        state = parts[-1].upper() if parts[-1].isalpha() else "STALE"

        if state not in LIVE_STATES:
            logging.debug(f"Skipping {parts[0]} — state: {state}")
            continue

        try:
            mac_idx = parts.index("lladdr") + 1
            dev_idx = parts.index("dev") + 1
        except ValueError:
            continue

        if mac_idx >= len(parts) or dev_idx >= len(parts):
            continue

        devices.append({
            "ip":        parts[0],
            "mac":       parts[mac_idx].lower(),
            "interface": parts[dev_idx].strip(),
            "state":     state,
        })

    return devices


def _from_arp_a() -> list[dict] | None:
    """
    Parse `arp -a` output as a fallback.
    State is always reported as UNKNOWN since arp -a does not expose it.

    Example line:
        ? (192.168.1.50) at 00:11:22:33:44:55 [ether] on enp3s0
    """
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True, text=True, check=True
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None

    pattern = re.compile(r'\((.*?)\) at ([0-9a-fA-F:]+) .* on (.*)')
    devices = []

    for line in result.stdout.splitlines():
        match = pattern.search(line)
        if match:
            ip, mac, iface = match.groups()
            devices.append({
                "ip":        ip,
                "mac":       mac.lower(),
                "interface": iface.strip(),
                "state":     "UNKNOWN",
            })

    return devices
