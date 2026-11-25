# ==================================================
# SECTION 3: WIRELESS PACKET COLLECTION AND PARSING
# ==================================================

from .section1_config import *
from . import section2_data as state
from .section2_data import access_points, clients, alerted_access_points, alerted_rogue_candidates
from .section4_security import audit_security
from .section5_analysis import detect_rogue_access_points

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

