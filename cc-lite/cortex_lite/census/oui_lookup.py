import csv
import os
import logging


class OUILookup:
    def __init__(self, csv_path: str = 'data/oui.csv'):
        self.registry = {}
        self._load_database(csv_path)

    def _load_database(self, csv_path: str):
        if not os.path.exists(csv_path):
            logging.warning(f"OUI database not found at {csv_path}. All devices will be 'Unknown'.")
            return

        try:
            with open(csv_path, mode='r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # IEEE uses 'Assignment' for the hex string without colons
                    oui = row.get('Assignment', '').lower().strip()
                    vendor = row.get('Organization Name', 'Unknown').strip()
                    if oui:
                        self.registry[oui] = vendor
        except Exception as e:
            logging.error(f"Failed to parse OUI database: {e}")

    def lookup(self, mac_address: str) -> tuple[str, str]:
        """
        Returns (vendor_name, confidence_level).
        Confidence level is a rough heuristic for the Profile B subset.
        """
        clean_mac = mac_address.lower().replace(':', '').replace('-', '')
        oui_prefix = clean_mac[:6]

        vendor = self.registry.get(oui_prefix, 'Unknown')

        # Immediate heuristic routing for tonight's validation
        vendor_lower = vendor.lower()
        confidence = 'low'

        if any(x in vendor_lower for x in ['espressif', 'tuya', 'ecobee', 'nest', 'wemo']):
            confidence = 'high'
        elif any(x in vendor_lower for x in ['apple', 'samsung', 'google', 'amazon']):
            confidence = 'medium'

        return vendor, confidence