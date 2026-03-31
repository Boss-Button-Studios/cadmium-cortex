import csv
import os
import re
import logging


# Vendors strongly associated with IoT device classes.
# Used to set confidence level heuristically where OUI alone is informative.
_HIGH_CONFIDENCE_IOT = {
    "espressif", "tuya", "ecobee", "nest", "wemo", "ring",
    "belkin", "lifx", "sengled", "lutron", "sonos", "august",
    "qingdao", "shenzhen",
}
_MEDIUM_CONFIDENCE_PERSONAL = {
    "apple", "samsung", "google", "amazon", "microsoft",
    "lenovo", "dell", "hp inc", "intel",
}


class OUILookup:
    def __init__(self, csv_path: str = "data/oui.csv",
                 txt_path: str = "data/oui.txt"):
        self.registry: dict[str, str] = {}
        self._load(csv_path, txt_path)

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load(self, csv_path: str, txt_path: str) -> None:
        """
        Load the OUI registry from whichever file is available.
        Prefers the IEEE text format (oui.txt) when both are present
        because it tends to be more complete and up to date.
        """
        if os.path.exists(txt_path):
            count = self._load_ieee_txt(txt_path)
            logging.info(f"OUI registry loaded from {txt_path} ({count} entries)")
            return

        if os.path.exists(csv_path):
            count = self._load_csv(csv_path)
            logging.info(f"OUI registry loaded from {csv_path} ({count} entries)")
            return

        logging.warning(
            f"No OUI database found at {txt_path!r} or {csv_path!r}. "
            "All devices will report vendor 'Unknown'."
        )

    def _load_ieee_txt(self, path: str) -> int:
        """
        Parse the standard IEEE OUI text file.

        The file alternates between hex-formatted lines and base-16 lines:
            28-6F-B9   (hex)    Nokia Shanghai Bell Co., Ltd.
            286FB9     (base 16) Nokia Shanghai Bell Co., Ltd.

        We key on the base-16 lines (no hyphens, no spaces) because they
        match the format we use for lookup.
        """
        # Matches:  286FB9     (base 16)     Vendor Name
        pattern = re.compile(
            r'^([0-9A-Fa-f]{6})\s+\(base 16\)\s+(.+)$'
        )
        count = 0
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    m = pattern.match(line.strip())
                    if m:
                        oui    = m.group(1).lower()
                        vendor = m.group(2).strip()
                        self.registry[oui] = vendor
                        count += 1
        except Exception as e:
            logging.error(f"Failed to parse IEEE OUI text file {path}: {e}")
        return count

    def _load_csv(self, path: str) -> int:
        """
        Parse the IEEE OUI CSV file (legacy format).
        Expects columns: 'Assignment', 'Organization Name'
        """
        count = 0
        try:
            with open(path, mode="r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    oui    = row.get("Assignment", "").lower().strip()
                    vendor = row.get("Organization Name", "Unknown").strip()
                    if oui:
                        self.registry[oui] = vendor
                        count += 1
        except Exception as e:
            logging.error(f"Failed to parse OUI CSV {path}: {e}")
        return count

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def lookup(self, mac_address: str) -> tuple[str, str]:
        """
        Look up a MAC address and return (vendor_name, confidence_level).

        Confidence levels:
          'none'   — locally administered (randomized) MAC; OUI is meaningless
          'high'   — OUI matches a known IoT/embedded vendor
          'medium' — OUI matches a known personal device vendor
          'low'    — OUI found but vendor class is ambiguous
          'unknown'— OUI not in registry
        """
        clean = mac_address.lower().replace(":", "").replace("-", "")

        # Locally administered bit: second-least-significant bit of first octet
        first_octet = int(clean[:2], 16)
        if first_octet & 0x02:
            return "Unknown (randomized MAC)", "none"

        oui    = clean[:6]
        vendor = self.registry.get(oui)

        if not vendor:
            return "Unknown", "unknown"

        vendor_lower = vendor.lower()
        if any(k in vendor_lower for k in _HIGH_CONFIDENCE_IOT):
            confidence = "high"
        elif any(k in vendor_lower for k in _MEDIUM_CONFIDENCE_PERSONAL):
            confidence = "medium"
        else:
            confidence = "low"

        return vendor, confidence
