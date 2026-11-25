
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, RadioTap, Dot11AssoResp, Dot11ReassoResp

import argparse
import csv
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

def discover_access_point(packet):

    # Check whether the packet contains a Wi-Fi beacon or probe response
    if not (packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp)):
        return

    # Get the access point MAC address
    bssid = packet[Dot11].addr3

    if not bssid:
        return

    # Read the Wi-Fi network name (SSID)
    ssid = "<Hidden>"

    element = packet.getlayer(Dot11Elt)

    while element:
        if element.ID == 0:
            ssid = element.info.decode(errors="replace")
            if not ssid:
                ssid = "<Hidden>"
            break

        element = element.payload.getlayer(Dot11Elt)

    # Read the Wi-Fi channel
    channel = "Unknown"

    element = packet.getlayer(Dot11Elt)

    while element:
        if element.ID == 3 and len(element.info) >= 1:
            channel = element.info[0]
            break

        element = element.payload.getlayer(Dot11Elt)

    # Read signal strength
    signal = "Unknown"

    if packet.haslayer(RadioTap):
        try:
            signal = packet[RadioTap].dBm_AntSignal
        except AttributeError:
            pass

    # Save or update the access point
    if bssid not in access_points:
        access_points[bssid] = {
            "SSID": ssid,
            "Channel": channel,
            "Signal": signal
        }
    else:
        old_ap = access_points[bssid]
        old_signal = old_ap.get("Signal", "Unknown")

        # Update hidden SSID when a visible SSID is received
        if ssid != "<Hidden>":
            old_ap["SSID"] = ssid

        # Update signal and channel when a stronger signal is received
        if isinstance(signal, int) and (
            not isinstance(old_signal, int) or signal > old_signal
        ):
            old_ap["Signal"] = signal

        if channel != "Unknown":
            old_ap["Channel"] = channel

    # Display discovered access points
    print("\n--- WiFiWatch: Discovered Access Points ---")

    for mac, details in access_points.items():
        print(f"SSID: {details['SSID']}")
        print(f"BSSID: {mac}")
        print(f"Channel: {details['Channel']}")
        print(f"Signal: {details['Signal']} dBm")
        print("-------------------------------------------")


def record_client(client_mac, event, bssid=None):

    if not client_mac:
        return

    client_mac = client_mac.lower()

    # Ignore broadcast and multicast addresses
    try:
        first_octet = int(client_mac.split(":")[0], 16)
        if first_octet & 1:
            return
    except (ValueError, IndexError):
        return

    # Create a record for a newly discovered client
    if client_mac not in clients:
        clients[client_mac] = {
            "probe_requests": 0,
            "association_requests": 0,
            "data_frames": 0,
            "events": set(),
            "access_points": set(),
            "observed_bssids": set(),
            "associated_bssids": set(),
            "association_candidates": set()
        }

    client = clients[client_mac]

    # Count observed activity
    if event == "probe":
        client["probe_requests"] += 1

    elif event == "association":
        client["association_requests"] += 1

    elif event == "data":
        client["data_frames"] += 1

    # Remember activity type
    new_event = event not in client["events"]
    client["events"].add(event)

    # Remember the access point
    new_ap = False

    if bssid and bssid.lower() != client_mac:

        bssid = bssid.lower()

        if bssid not in client["access_points"]:
            client["access_points"].add(bssid)
            new_ap = True

        if event == "association":
            client["association_candidates"].add(bssid)

        elif event == "data":
            client["observed_bssids"].add(bssid)

        elif event == "association_confirmed":
            client["associated_bssids"].add(bssid)

    # Display newly discovered clients or activity
    if len(client["events"]) == 1 and sum(
        client[k] for k in (
            "probe_requests",
            "association_requests",
            "data_frames"
        )
    ) == 1:
        print(f"\nNew client observed: {client_mac}")

    elif new_event or new_ap:
        print(f"\nClient activity: {client_mac}")
        print(f"Activity type: {event}")

    if new_ap:
        print(f"Access point candidate: {bssid}")

def discover_client(packet):

    if not packet.haslayer(Dot11):
        return

    dot11 = packet[Dot11]

    # 1. Probe Request
    # Management frame subtype = 4
    if dot11.type == 0 and dot11.subtype == 4:

        print("PROBE REQUEST DETECTED:", dot11.addr2)

        record_client(
            client_mac=dot11.addr2,
            event="probe"
        )

    # 2. Association Request or Reassociation Request
    # Subtype 0 = Association Request
    # Subtype 2 = Reassociation Request
    elif dot11.type == 0 and dot11.subtype in (0, 2):

        record_client(
            client_mac=dot11.addr2,
            event="association",
            bssid=dot11.addr1
        )

    # 3. Association Response or Reassociation Response
    # Subtype 1 = Association Response
    # Subtype 3 = Reassociation Response
    elif dot11.type == 0 and dot11.subtype in (1, 3):

        if dot11.subtype == 1:
            response = packet.getlayer(Dot11AssoResp)
        else:
            response = packet.getlayer(Dot11ReassoResp)

        if response and getattr(response, "status", None) == 0:

            record_client(
                client_mac=dot11.addr1,
                event="association_confirmed",
                bssid=dot11.addr2
            )

            print(
                f"ASSOCIATION CONFIRMED: "
                f"{dot11.addr1} -> {dot11.addr2}"
            )

    # 4. Data Frames
    elif dot11.type == 2:

        frame_control = int(dot11.FCfield)

        to_ds = frame_control & 0x01
        from_ds = frame_control & 0x02

        # Client sending data to an access point
        if to_ds and not from_ds:

            record_client(
                client_mac=dot11.addr2,
                event="data",
                bssid=dot11.addr1
            )

        # Access point sending data to a client
        elif from_ds and not to_ds:

            record_client(
                client_mac=dot11.addr1,
                event="data",
                bssid=dot11.addr2
            )

def decode_suites(data, count, offset):
    """Read cipher or authentication suite selectors."""
    suites = {
        0: "Use group cipher",
        1: "WEP-40",
        2: "TKIP",
        4: "CCMP",
        5: "WEP-104",
        8: "GCMP",
        9: "GCMP-256",
        10: "CCMP-256"
    }

    result = []

    for _ in range(count):
        if offset + 4 > len(data):
            break

        suite = data[offset:offset + 4]
        result.append(suites.get(suite[3], f"Unknown ({suite.hex()})"))
        offset += 4

    return result, offset


def parse_security_info(info, wpa=False):

    """Parse the cipher and authentication suites in RSN or WPA information."""
    if wpa:
        # Skip WPA vendor identifier: 00:50:F2:01
        info = info[4:]

    if len(info) < 8:
        return [], [], []

    offset = 2  # Skip version
    group_cipher = info[offset:offset + 4]
    offset += 4

    group_name = {
        1: "WEP-40",
        2: "TKIP",
        4: "CCMP",
        5: "WEP-104",
        8: "GCMP",
        9: "GCMP-256",
        10: "CCMP-256"
    }.get(group_cipher[3], "Unknown")

    if offset + 2 > len(info):
        return [group_name], [], []

    pairwise_count = int.from_bytes(info[offset:offset + 2], "little")
    offset += 2

    pairwise, offset = decode_suites(info, pairwise_count, offset)

    if offset + 2 > len(info):
        return [group_name], pairwise, []

    akm_count = int.from_bytes(info[offset:offset + 2], "little")
    offset += 2

    akm_names = {
        1: "802.1X",
        2: "PSK",
        8: "SAE",
        18: "OWE"
    }

    authentication = []

    for _ in range(akm_count):
        if offset + 4 > len(info):
            break

        suite = info[offset:offset + 4]
        authentication.append(
            akm_names.get(suite[3], f"Unknown ({suite.hex()})")
        )
        offset += 4

    return [group_name], pairwise, authentication

def parse_pmf_capabilities(info):
    """Extract PMF capabilities from an RSN information element."""

    offset = 2 + 4

    if offset + 2 > len(info):
        return False, False

    pairwise_count = int.from_bytes(info[offset:offset+2], "little")
    offset += 2

    if pairwise_count > (len(info) - offset) // 4:
        return False, False

    offset += pairwise_count * 4

    if offset + 2 > len(info):
        return False, False

    akm_count = int.from_bytes(info[offset:offset+2], "little")
    offset += 2

    if akm_count > (len(info) - offset) // 4:
        return False, False

    offset += akm_count * 4

    if offset + 2 > len(info):
        return False, False

    capabilities = int.from_bytes(info[offset:offset+2], "little")

    pmf_capable = bool(capabilities & 0x0040)
    pmf_required = bool(capabilities & 0x0080)

    return pmf_capable, pmf_required


def audit_security(packet):

    """Passively audit the security information in an access point beacon."""

    if not (packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp)):
        return

    dot11 = packet.getlayer(Dot11)
    beacon = packet.getlayer(Dot11Beacon) or packet.getlayer(Dot11ProbeResp)
    bssid = dot11.addr2

    if not bssid:
        return

    privacy_enabled = bool(int(beacon.cap) & 0x10)

    rsn_found = False
    wpa_found = False
    wps_found = False
    pmf_capable = False
    pmf_required = False

    group_ciphers = []
    pairwise_ciphers = []
    authentication = []

    element = packet.getlayer(Dot11Elt)

    while isinstance(element, Dot11Elt):

        # RSN information element: ID 48
        if element.ID == 48:
            rsn_found = True
            pmf_capable, pmf_required = parse_pmf_capabilities(
            bytes(element.info)
            )

            group, pairwise, auth = parse_security_info(
                bytes(element.info)
            )

            group_ciphers.extend(group)
            pairwise_ciphers.extend(pairwise)
            authentication.extend(auth)

        # Vendor-specific information element: ID 221
        elif element.ID == 221:
            info = bytes(element.info)

            # WPA vendor information: 00:50:F2:01
            if info.startswith(b"\x00\x50\xf2\x01"):
                wpa_found = True

                group, pairwise, auth = parse_security_info(
                    info, wpa=True
                )

                group_ciphers.extend(group)
                pairwise_ciphers.extend(pairwise)
                authentication.extend(auth)

            # WPS vendor information: 00:50:F2:04
            elif info.startswith(b"\x00\x50\xf2\x04"):
                wps_found = True

        next_element = element.payload

        if not isinstance(next_element, Dot11Elt):
            break

        element = next_element

    # Classify the network
    if rsn_found and "OWE" in authentication:
        security = "Enhanced Open (OWE)"

    elif rsn_found and "SAE" in authentication and "PSK" in authentication:
        security = "WPA2/WPA3 transition"

    elif rsn_found and "SAE" in authentication:
        if pmf_capable and pmf_required:
            security = "WPA3-Personal"
        else:
            security = "SAE (PMF requirements not met)"

    elif rsn_found:
        security = "WPA2"

    elif wpa_found:
        security = "WPA"

    elif privacy_enabled:
        security = "WEP"

    else:
        security = "Open"

    all_ciphers = group_ciphers + pairwise_ciphers
    tkip_detected = "TKIP" in all_ciphers
    wpa_tkip_warning = security == "WPA" and tkip_detected

    security_audits[bssid] = {
        "security": security,
        "group_ciphers": sorted(set(group_ciphers)),
        "pairwise_ciphers": sorted(set(pairwise_ciphers)),
        "authentication": sorted(set(authentication)),
        "wps": wps_found,
        "tkip": tkip_detected,
        "wpa_tkip_warning": wpa_tkip_warning
    }

    print("\n[SECURITY AUDIT]", flush=True)
    print("BSSID:", bssid, flush=True)
    print("Security:", security, flush=True)
    print("Group ciphers:", group_ciphers, flush=True)
    print("Pairwise ciphers:", pairwise_ciphers, flush=True)
    print("Authentication:", authentication, flush=True)
    print("PMF Capable:", pmf_capable, flush=True)
    print("PMF Required:", pmf_required, flush=True)
    print("WPS enabled:", wps_found, flush=True)
    print("TKIP detected:", tkip_detected, flush=True)
    if wpa_tkip_warning:
        print("WARNING: WPA with TKIP detected - weak encryption!", flush=True)

def print_security_summary():

    print("\n========== SECURITY SUMMARY ==========")
    print("\n========== INDIVIDUAL SECURITY AUDITS ==========")

    for bssid, details in security_audits.items():
        print("\n[SECURITY AUDIT]")
        print("BSSID:", bssid)
        print("Security:", details["security"])
        print("Group ciphers:", details["group_ciphers"])
        print("Pairwise ciphers:", details["pairwise_ciphers"])
        print("Authentication:", details["authentication"])
        print("WPS enabled:", details["wps"])
        print("TKIP detected:", details["tkip"])

    open_count = 0
    wep_count = 0
    wpa_tkip_count = 0
    wps_count = 0
    wpa2_count = 0
    wpa3_count = 0

    for bssid, details in security_audits.items():

        security = details["security"]

        if security == "Open":
            open_count += 1

        elif security == "WEP":
            wep_count += 1

        elif security == "WPA2":
            wpa2_count += 1

        elif security in ("WPA3", "WPA3-Personal"):
            wpa3_count += 1

        elif security == "WPA2/WPA3 transition":
            wpa2_count += 1
            wpa3_count += 1

        if details["tkip"]:
            wpa_tkip_count += 1

        if details["wps"]:
            wps_count += 1

    print("Audited access points:", len(security_audits))
    print("Open networks:", open_count)
    print("WEP networks:", wep_count)
    print("WPA2 networks:", wpa2_count)
    print("WPA3 networks:", wpa3_count)
    print("Networks using TKIP:", wpa_tkip_count)
    print("Networks with WPS detected:", wps_count)

    print("======================================")

def detect_rogue_access_points():

    if not BASELINE_LOADED or not KNOWN_GOOD_BASELINE:
        return None

    rogue_candidates = []

    for bssid, ap_details in access_points.items():

        ssid = ap_details.get("SSID", "")
        observed_bssid = bssid.lower()

        observed_security = security_audits.get(
            bssid, {}
        ).get("security", "Unknown")

        trusted_entries = [
            entry for entry in KNOWN_GOOD_BASELINE
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

def build_report_data():

    rogue_candidates = detect_rogue_access_points()
    channel_analysis = analyze_channels()

    # Sort access points by strongest signal first
    sorted_aps = sorted(
        access_points.items(),
        key=lambda item: (
            isinstance(item[1]["Signal"], int),
            item[1]["Signal"] if isinstance(item[1]["Signal"], int) else -999
        ),
        reverse=True
    )

    ap_report = []

    for bssid, details in sorted_aps:
        ap_report.append({
            "BSSID": bssid,
            "SSID": details["SSID"],
            "Channel": details["Channel"],
            "Signal": details["Signal"]
        })

    client_report = []

    for mac, details in clients.items():
        client_report.append({
            "MAC": mac,
            "probe_requests": details["probe_requests"],
            "association_requests": details["association_requests"],
            "data_frames": details["data_frames"],
            "csv_packets": details.get("csv_packets"),
            "access_points": sorted(details["access_points"]),
            "associated_bssids": sorted(details["associated_bssids"]),
            "association_candidates": sorted(
                details["association_candidates"]
            ),
            "events": sorted(details["events"])
        })

    # Prepare security information for JSON
    security_report = {}

    for bssid, details in security_audits.items():
        security_report[bssid] = {
            "security": details["security"],
            "group_ciphers": details["group_ciphers"],
            "pairwise_ciphers": details["pairwise_ciphers"],
            "authentication": details["authentication"],
            "wps": details["wps"],
            "tkip": details["tkip"]
        }

    open_count = sum(
        1 for item in security_audits.values()
        if item["security"] == "Open"
    )

    wep_count = sum(
        1 for item in security_audits.values()
        if item["security"] == "WEP"
    )

    wpa2_count = sum(
        1 for item in security_audits.values()
        if item["security"] in ("WPA2", "WPA2/WPA3 transition")
    )

    wpa3_count = sum(
        1 for item in security_audits.values()
        if item["security"] in (
           "WPA3",
           "WPA3-Personal",
           "WPA2/WPA3 transition")
    )

    tkip_count = sum(
        1 for item in security_audits.values()
        if item["tkip"]
    )

    wps_count = sum(
        1 for item in security_audits.values()
        if item["wps"] is True
    )

    summary = {
        "total_access_points": len(access_points),
        "total_clients": len(clients),
        "audited_access_points": len(security_audits),
        "open_networks": open_count,
        "wep_networks": wep_count,
        "wpa2_networks": wpa2_count,
        "wpa3_networks": wpa3_count,
        "networks_using_tkip": tkip_count,
        "networks_with_wps_detected": wps_count,
        "total_rogue_candidates": len(rogue_candidates)
    }

    return {
    "access_points": ap_report,
    "clients": client_report,
    "security_audits": security_report,
    "rogue_candidates": rogue_candidates,
    "channel_analysis": channel_analysis,
    "summary": summary
}

def write_json_report(filename, report_data):

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(report_data, file, indent=4)

    print("JSON report saved:", filename)


def write_txt_report(filename, report_data):

    with open(filename, "w", encoding="utf-8") as file:

        file.write("========== WIFIWATCH REPORT ==========\n")

        file.write("\n========== ACCESS POINTS ==========\n")

        for ap in report_data["access_points"]:
            file.write(f"\nSSID: {ap['SSID']}\n")
            file.write(f"BSSID: {ap['BSSID']}\n")
            file.write(f"Channel: {ap['Channel']}\n")
            file.write(f"Signal: {ap['Signal']}\n")

        file.write("\n========== WIRELESS CLIENTS ==========\n")

        for client in report_data["clients"]:
            file.write(f"\nClient MAC: {client['MAC']}\n")
            file.write(
                f"Probe requests: {client['probe_requests']}\n"
            )
            file.write(
                f"Association requests: {client['association_requests']}\n"
            )
            file.write(f"Data frames: {client['data_frames']}\n")

            if client["csv_packets"] is not None:
                file.write(f"CSV packet count: {client['csv_packets']}\n")

            file.write(
                f"Associated BSSIDs: {client['associated_bssids']}\n"
            )

        file.write("\n========== SECURITY AUDITS ==========\n")

        for bssid, details in report_data["security_audits"].items():
            file.write(f"\nBSSID: {bssid}\n")
            file.write(f"Security: {details['security']}\n")
            file.write(
                f"Group ciphers: {details['group_ciphers']}\n"
            )
            file.write(
                f"Pairwise ciphers: {details['pairwise_ciphers']}\n"
            )
            file.write(
                f"Authentication: {details['authentication']}\n"
            )

            if details["wps"] is None:
                wps_status = "Not available in CSV"
            else:
                wps_status = details["wps"]

            file.write(f"WPS enabled: {wps_status}\n")
            file.write(f"TKIP detected: {details['tkip']}\n")

        file.write("\n========== ROGUE AP REPORT ==========\n")

        if report_data["rogue_candidates"]:
            for ap in report_data["rogue_candidates"]:
                file.write(f"\nSSID: {ap['SSID']}\n")
                file.write(f"BSSID: {ap['BSSID']}\n")
                file.write(f"Security: {ap['security']}\n")
                file.write(f"Reasons: {ap['reasons']}\n")
        else:
            file.write("No rogue AP candidates detected.\n")
        # Channel Analysis
        channel_data = report_data["channel_analysis"]

        file.write("\n========== CHANNEL ANALYSIS ==========\n")

        file.write("\nAccess Points Per Channel:\n")

        for channel, count in channel_data["channel_counts"].items():
            file.write(
                f"Channel {channel}: {count} access point(s)\n"
            )

        file.write("\nCongested Channels:\n")

        if channel_data["congested_channels"]:

            for item in channel_data["congested_channels"]:
                file.write(
                    f"Channel {item['channel']}: "
                    f"{item['access_points']} APs - "
                    f"{item['status']}\n"
                )
        else:
            file.write("No congested channels detected.\n")

        file.write("\nPotentially Overlapping Channels:\n")

        if channel_data["overlapping_channels"]:

            for item in channel_data["overlapping_channels"]:
                file.write(
                    f"Channel {item['channel_1']} and "
                    f"Channel {item['channel_2']} may overlap.\n"
                )
        else:
            file.write("No overlapping channels detected.\n")
        file.write("\n========== SUMMARY ==========\n")

        for key, value in report_data["summary"].items():
            file.write(f"{key}: {value}\n")

        file.write("\n======================================\n")

    print("TXT report saved:", filename)

def alert_new_access_point(bssid):

    details = access_points.get(bssid)

    if not details or bssid in alerted_access_points:
        return

    alerted_access_points.add(bssid)

    ssid = details.get("SSID", "<Hidden>")
    channel = details.get("Channel", "Unknown")
    security = details.get("Security", "Unknown")
    signal = details.get("Signal", "Unknown")

    print("\n" + "!" * 45)
    print("[NEW ACCESS POINT DETECTED]")
    print(f"SSID:     {ssid}")
    print(f"BSSID:    {bssid}")
    print(f"Channel:  {channel}")
    print(f"Security: {security}")
    print(f"Signal:   {signal}")
    print("!" * 45)

    # Rogue detection requires a loaded baseline.
    if not BASELINE_LOADED or not KNOWN_GOOD_BASELINE:
        return

    rogue_candidates = detect_rogue_access_points()

    for ap in rogue_candidates or []:

        if ap["BSSID"] != bssid:
            continue

        if bssid in alerted_rogue_candidates:
            continue

        alerted_rogue_candidates.add(bssid)

        print("\n" + "!" * 45)
        print("[ROGUE ACCESS POINT CANDIDATE]")
        print(f"SSID: {ap['SSID']}")
        print(f"BSSID: {ap['BSSID']}")

        for reason in ap["reasons"]:
            print("Reason:", reason)

        print("!" * 45 + "\n")

def process_packet(packet, watch=False):

    if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):

        bssid = packet[Dot11].addr3

        is_new = (
            bssid is not None
            and bssid not in access_points
        )

        discover_access_point(packet)

        if watch and is_new and bssid in access_points:
            alert_new_access_point(bssid)

    discover_client(packet)
    audit_security(packet)

def run_live_capture(interface, watch=False):
    try:
        if watch:
            print("\n[WiFiWatch] Continuous Watch Mode is active.")
            print("[WiFiWatch] Listening for new access points and rogue candidates...")
            print("[WiFiWatch] Press Ctrl+C to stop.\n")

            sniff(
                iface=interface,
                prn=lambda packet: process_packet(packet, watch=True),
                store=False
            )
        else:
            sniff(
                iface=interface,
                prn=process_packet,
                store=False
            )

    except KeyboardInterrupt:
        print("\n[WiFiWatch] Monitoring stopped by user.")

def print_final_report():

    print("\n========== FINAL REPORT ==========")

    print("Total access points discovered:", len(access_points))
    print("Total clients discovered:", len(clients))

    print("\n--- Access Point Discovery Results ---")

    if not access_points:
        print("No access points discovered.")

    else:
        sorted_aps = sorted(
            access_points.items(),
            key=lambda item: (
                isinstance(item[1]["Signal"], int),
                item[1]["Signal"]
                if isinstance(item[1]["Signal"], int)
                else -999
            ),
            reverse=True
        )

        for bssid, details in sorted_aps:

            print("\nSSID:", details["SSID"])
            print("BSSID:", bssid)
            print("Channel:", details["Channel"])
            print("Signal:", details["Signal"], "dBm")

            security = security_audits.get(
                bssid, {}
            ).get("security", "Unknown")

            print("Security:", security)
            print("-----------------------------------")

    print("\n--- Client Discovery Results ---")

    if not clients:
        print("No clients discovered.")

    for mac, details in clients.items():

        print("\nClient MAC:", mac)
        print("Probe requests:", details["probe_requests"])
        print("Association requests:", details["association_requests"])
        print("Data frames:", details["data_frames"])

        if "csv_packets" in details:
            print("CSV packet count:", details["csv_packets"])

        print("\nObserved AP Relationships:")

        observed = details.get("observed_bssids", set())

        if observed:
            for ap in sorted(observed):
                print(" ", ap)
        else:
            print(" None")

        print("\nAssociation Candidates:")

        candidates = details.get("association_candidates", set())

        if candidates:
            for ap in sorted(candidates):
                print(" ", ap)
        else:
            print(" None")

        print("\nConfirmed Associations:")

        confirmed = details.get("associated_bssids", set())

        if confirmed:
            for ap in sorted(confirmed):
                print(" ", ap)
        else:
            print(" None")

    print_security_summary()
    print_rogue_report()
    print_channel_analysis()
    print("\n=================================")

def main():

    parser = argparse.ArgumentParser(
        description="WiFiWatch - Passive Wi-Fi Security Monitoring"
    )

    parser.add_argument(
        "--csv",
        dest="csv_file",
        help="Load an airodump-ng CSV file instead of live capture"
    )

    parser.add_argument(
        "--interface",
        default="wlan0",
        help="Wireless monitor interface (default: wlan0)"
    )

    parser.add_argument(
        "--txt-report",
        default="wifiwatch_report.txt",
        help="TXT report filename"
    )

    parser.add_argument(
        "--json-report",
        default="wifiwatch_report.json",
        help="JSON report filename"
    )

    parser.add_argument(
        "--watch",
        action="store_true",
        help="Continuously monitor and alert on new access points"
    )

    parser.add_argument(
    "--baseline",
    help="Optional JSON file containing trusted access points"
    )

    args = parser.parse_args()

    if args.baseline:
        if not load_baseline(args.baseline):
            parser.error("Could not load baseline file.")
    else:
        print("[WiFiWatch] No baseline supplied; rogue detection unavailable.")


    # Choose CSV input or live passive capture
    if args.csv_file:
        load_airodump_csv(args.csv_file)

    else:
        run_live_capture(args.interface, watch=args.watch)

    # Display final results
    print_final_report()

    # Prepare and save reports
    report_data = build_report_data()

    write_txt_report(
        args.txt_report,
        report_data
    )

    write_json_report(
        args.json_report,
        report_data
    )


if __name__ == "__main__":
    main()

