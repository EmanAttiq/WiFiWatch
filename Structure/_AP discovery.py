# ====================================================================
#  WIRELESS ACCESS POINT DISCOVERY AND CLIENT TRACKING
# ====================================================================

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
    
