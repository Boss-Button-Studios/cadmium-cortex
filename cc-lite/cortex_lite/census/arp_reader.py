import subprocess
import re
import logging


def get_arp_table(interface="wlp3s0"):
    """Reads the local ARP cache without requiring root privileges."""
    devices = []

    try:
        # Try traditional arp command first
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True, check=True)
        # Matches Mint/Ubuntu output: ? (192.168.1.50) at 00:11:22:33:44:55 [ether] on enp3s0
        pattern = re.compile(r'\((.*?)\) at ([0-9a-fA-F:]+) .* on (.*)')

        for line in result.stdout.splitlines():
            match = pattern.search(line)
            if match:
                ip, mac, iface = match.groups()
                devices.append({
                    'mac': mac.lower(),
                    'ip': ip,
                    'interface': iface.strip()
                })
        return devices

    except (FileNotFoundError, subprocess.CalledProcessError):
        # Fallback to iproute2 (standard on modern Linux)
        try:
            result = subprocess.run(['ip', 'neigh', 'show'], capture_output=True, text=True, check=True)
            # Matches: 192.168.1.50 dev enp3s0 lladdr 00:11:22:33:44:55 REACHABLE
            for line in result.stdout.splitlines():
                parts = line.split()
                if 'lladdr' in parts:
                    mac_idx = parts.index('lladdr') + 1
                    dev_idx = parts.index('dev') + 1

                    if mac_idx < len(parts) and dev_idx < len(parts):
                        devices.append({
                            'mac': parts[mac_idx].lower(),
                            'ip': parts[0],
                            'interface': parts[dev_idx]
                        })
            return devices

        except FileNotFoundError:
            logging.error("Neither 'arp' nor 'ip' commands found. Ensure net-tools or iproute2 is installed.")
            return []
