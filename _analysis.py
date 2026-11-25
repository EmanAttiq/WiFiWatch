# ==================================================
# SECTION 5: WIRELESS NETWORK ANALYSIS
# ==================================================

from .section1_config import *
from . import section2_data as state
from .section2_data import access_points, clients, security_audits

def detect_rogue_access_points():

    if not state.BASELINE_LOADED or not state.KNOWN_GOOD_BASELINE:
        return None

    rogue_candidates = []

    for bssid, ap_details in access_points.items():

        ssid = ap_details.get("SSID", "")
        observed_bssid = bssid.lower()

        observed_security = security_audits.get(
            bssid, {}
        ).get("security", "Unknown")

        trusted_entries = [
            entry for entry in state.KNOWN_GOOD_BASELINE
            if entry["SSID"] == ssid
        ]

        if not trusted_entries:
            continue

        expected_pairs = {
            (
                entry["BSSID"].lower(),
                entry["security"]
            )
            for entry in trusted_entries
        }

        expected_bssids = {
            entry["BSSID"].lower()
            for entry in trusted_entries
        }

        expected_security = {
            entry["security"]
            for entry in trusted_entries
        }

        reasons = []

        if observed_bssid not in expected_bssids:
            reasons.append("BSSID differs from trusted baseline")

        if observed_security != "Unknown":
            if observed_security not in expected_security:
                reasons.append(
                    "Encryption differs from trusted baseline"
                )
            elif (observed_bssid, observed_security) not in expected_pairs:
                reasons.append(
                    "BSSID and security combination differs "
                    "from trusted baseline"
                )

        if reasons:
            rogue_candidates.append({
                "SSID": ssid,
                "BSSID": bssid,
                "security": observed_security,
                "reasons": reasons
            })

    return rogue_candidates


def print_rogue_report():

    rogue_candidates = detect_rogue_access_points()

    print("\n========== ROGUE ACCESS POINT REPORT ==========")

    if rogue_candidates is None:
        print("Baseline not loaded.")
        print("Rogue AP detection unavailable.")
        return

    if rogue_candidates:
        for ap in rogue_candidates:
            print("\n[ROGUE ACCESS POINT CANDIDATE]")
            print("SSID:", ap["SSID"])
            print("BSSID:", ap["BSSID"])
            print("Security:", ap["security"])

            for reason in ap["reasons"]:
                print("Reason:", reason)

    else:
        print("No rogue access point candidates detected.")

    print("\nTotal rogue candidates:", len(rogue_candidates))
    print("===============================================")


def load_airodump_csv(csv_file):
    """Load AP and client information from an airodump-ng CSV file."""

    print("\nLoading CSV file:", csv_file)

    with open(csv_file, "r", newline="", encoding="utf-8-sig") as file:
        rows = list(csv.reader(file))

    section = None
    ap_header = []
    client_header = []

    for row in rows:
        row = [value.strip() for value in row]

        # Identify the access point table
        if row and row[0] == "BSSID" and "ESSID" in row:
            ap_header = row
            section = "access_points"
            continue

        # Identify the wireless client table
        if row and row[0] == "Station MAC":
            client_header = row
            section = "clients"
            continue

        if not row or not any(row):
            continue

        # Process access points
        if section == "access_points" and ap_header:

            details = dict(zip(ap_header, row))

            bssid = details.get("BSSID", "").lower()

            if not bssid:
                continue

            ssid = details.get("ESSID", "") or "<Hidden>"

            channel = details.get("channel", "Unknown")
            try:
                channel = int(channel)
            except (ValueError, TypeError):
                pass

            signal = details.get("Power", "Unknown")
            try:
                signal = int(signal)
            except (ValueError, TypeError):
                pass

            access_points[bssid] = {
                "SSID": ssid,
                "Channel": channel,
                "Signal": signal
            }

            privacy = details.get("Privacy", "").upper()
            cipher_text = details.get("Cipher", "").upper()
            auth_text = details.get("Authentication", "").upper()

            # Determine the security type from CSV fields
            if "SAE" in auth_text and "PSK" in auth_text:
                security = "WPA2/WPA3 transition"
            elif "SAE" in auth_text or "WPA3" in privacy:
                security = "WPA3"
            elif "WPA2" in privacy:
                security = "WPA2"
            elif "WPA" in privacy:
                security = "WPA"
            elif "WEP" in privacy:
                security = "WEP"
            else:
                security = "Open"

            ciphers = [
                item for item in cipher_text.split()
                if item not in ("", "NONE")
            ]

            authentication = [
                item for item in auth_text.split()
                if item not in ("", "NONE")
            ]

            security_audits[bssid] = {
                "security": security,
                "group_ciphers": [],
                "pairwise_ciphers": ciphers,
                "authentication": authentication,
                "wps": None,
                "tkip": "TKIP" in cipher_text
            }

        # Process wireless clients
        elif section == "clients" and client_header:

            details = dict(zip(client_header, row))

            client_mac = details.get("Station MAC", "").lower()

            if not client_mac:
                continue

            bssid = details.get("BSSID", "").lower()

            # Ignore unassociated-client markers
            if bssid in ("", "(not associated)", "not associated"):
                bssid = None

            packets = details.get("# packets", "0")

            try:
                packets = int(packets)
            except (ValueError, TypeError):
                packets = 0

            if client_mac not in clients:

                clients[client_mac] = {
                    "probe_requests": 0,
                    "association_requests": 0,
                    "data_frames": 0,
                    "events": {"csv"},
                    "access_points": set(),
                    "observed_bssids": set(),
                    "association_candidates": set(),
                    "associated_bssids": set(),
                    "csv_reported_bssids": set(),
                    "csv_packets": packets
                }

            else:
                client = clients[client_mac]

                client.setdefault("observed_bssids", set())
                client.setdefault("association_candidates", set())
                client.setdefault("associated_bssids", set())
                client.setdefault("csv_reported_bssids", set())
                client.setdefault("access_points", set())
                client.setdefault("csv_packets", 0)

                client["csv_packets"] += packets

            # Store CSV-reported AP relationships separately
            if bssid:
                clients[client_mac]["access_points"].add(bssid)

                clients[client_mac]["csv_reported_bssids"].add(bssid)

    print("CSV import completed.")
    print("Access points loaded:", len(access_points))
    print("Clients loaded:", len(clients))


def analyze_channels():

    channel_counts = {}

    # Count access points on each channel
    for bssid, details in access_points.items():

        channel = details.get("channel", details.get("Channel", "Unknown"))

        try:
            channel = int(channel)
        except (ValueError, TypeError):
            channel = "Unknown"

        if channel == "Unknown":
            continue

        channel_counts[channel] = channel_counts.get(channel, 0) + 1

    # Sort channels numerically
    sorted_channels = dict(sorted(channel_counts.items()))

    # Identify congestion
    congested_channels = []

    for channel, count in sorted_channels.items():

        if count >= 3:
            congested_channels.append({
                "channel": channel,
                "access_points": count,
                "status": "High congestion"
            })

        elif count == 2:
            congested_channels.append({
                "channel": channel,
                "access_points": count,
                "status": "Moderate congestion"
            })

    # Identify potentially overlapping 2.4 GHz channels
    channels_24ghz = [
        channel for channel in sorted_channels
        if 1 <= channel <= 14
    ]

    overlapping_channels = []

    for i, channel1 in enumerate(channels_24ghz):

        for channel2 in channels_24ghz[i + 1:]:

            # Channels within four channel numbers may overlap
            if abs(channel1 - channel2) <= 4:

                overlapping_channels.append({
                    "channel_1": channel1,
                    "channel_2": channel2,
                    "aps_on_channel_1": sorted_channels[channel1],
                    "aps_on_channel_2": sorted_channels[channel2]
                })

    return {
        "channel_counts": sorted_channels,
        "congested_channels": congested_channels,
        "overlapping_channels": overlapping_channels
    }


def print_channel_analysis():

    analysis = analyze_channels()

    print("\n========== CHANNEL ANALYSIS ==========")

    if not analysis["channel_counts"]:
        print("No channel information available.")

    else:
        print("\nAccess Points Per Channel:")

        for channel, count in analysis["channel_counts"].items():
            print(f"Channel {channel}: {count} access point(s)")

        print("\nCongested Channels:")

        if analysis["congested_channels"]:

            for item in analysis["congested_channels"]:
                print(
                    f"Channel {item['channel']}: "
                    f"{item['access_points']} APs - "
                    f"{item['status']}"
                )
        else:
            print("No moderately or highly congested channels.")

        print("\nPotentially Overlapping 2.4 GHz Channels:")

        if analysis["overlapping_channels"]:

            for item in analysis["overlapping_channels"]:
                print(
                    f"Channel {item['channel_1']} "
                    f"and Channel {item['channel_2']} "
                    f"may overlap."
                )
        else:
            print("No overlapping 2.4 GHz channels detected.")

    print("======================================")

