# ==================================================
# SECTION 2: DATA STRUCTURES AND INITIALIZATION
# ==================================================

import json

# Store discovered access points
access_points = {}

# Store discovered wireless clients
clients = {}

security_audits = {}

# Optional user-defined trusted access point baseline
KNOWN_GOOD_BASELINE = []
BASELINE_LOADED = False
alerted_access_points = set()
alerted_rogue_candidates = set()

def load_baseline(filename):
    global KNOWN_GOOD_BASELINE, BASELINE_LOADED

    KNOWN_GOOD_BASELINE = []
    BASELINE_LOADED = False

    try:
        with open(filename, "r", encoding="utf-8") as file:
            data = json.load(file)

        if not isinstance(data, list):
            raise ValueError("Baseline must contain a JSON list.")

        validated_entries = []

        for entry in data:
            if not isinstance(entry, dict):
                raise ValueError("Each baseline entry must be an object.")

            ssid = entry.get("SSID")
            bssid = entry.get("BSSID")
            security = entry.get("security")

            if not all(
                isinstance(value, str) and value.strip()
                for value in (ssid, bssid, security)
            ):
                raise ValueError(
                    "Each entry requires SSID, BSSID and security."
                )

            bssid = bssid.strip().lower()

            parts = bssid.split(":")
            if len(parts) != 6 or any(
                len(part) != 2
                or any(char not in "0123456789abcdef" for char in part)
                for part in parts
            ):
                raise ValueError(f"Invalid BSSID: {bssid}")

            validated_entries.append({
                "SSID": ssid.strip(),
                "BSSID": bssid,
                "security": security.strip()
            })

        KNOWN_GOOD_BASELINE = validated_entries
        BASELINE_LOADED = True

        print(
            f"[WiFiWatch] Loaded {len(KNOWN_GOOD_BASELINE)} "
            "trusted access point(s)."
        )
        return True

    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"[WiFiWatch] Baseline error: {error}")
        return False

