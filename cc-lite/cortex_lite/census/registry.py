import json
import hashlib
import os
import time
from datetime import datetime

class DeviceRegistry:
    def __init__(self, registry_path='data/registry.json'):
        self.path = registry_path
        self.devices = self._load()

    def _load(self):
        if os.path.exists(self.path):
            with open(self.path, 'r') as f:
                return json.load(f)
        return {}

    def _hash_mac(self, mac: str) -> str:
        """Section 9 Compliance: SHA-256 hash of the MAC address."""
        return hashlib.sha256(mac.lower().strip().encode()).hexdigest()

    def update_devices(self, observed_list, oui_lookup_tool):
        new_discoveries = 0
        for obs in observed_list:
            dev_id = self._hash_mac(obs['mac'])
            vendor, confidence = oui_lookup_tool.lookup(obs['mac'])
            
            if dev_id not in self.devices:
                self.devices[dev_id] = {
                    "device_id": dev_id,
                    "vendor": vendor,
                    "classification_confidence": confidence,
                    "first_seen": datetime.utcnow().isoformat(),
                    "observed_ips": [obs['ip']],
                    "interface": obs['interface'],
                    "trust_tier": "pending"
                }
                new_discoveries += 1
            else:
                # Update volatile data
                if obs['ip'] not in self.devices[dev_id]["observed_ips"]:
                    self.devices[dev_id]["observed_ips"].append(obs['ip'])
            
            self.devices[dev_id]["last_seen"] = datetime.utcnow().isoformat()
        
        self._save()
        return new_discoveries

    def _save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, 'w') as f:
            json.dump(self.devices, f, indent=4)

    def get_audit_summary(self):
        """Returns a sanitized list for the LLM."""
        return [
            {
                "device_id": d["device_id"],
                "vendor": d["vendor"],
                "confidence": d["classification_confidence"],
                "ips": d["observed_ips"]
            } for d in self.devices.values()
        ]
