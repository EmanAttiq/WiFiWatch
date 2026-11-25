# ====================================================================
# WIRELESS SECURITY ANALYSIS AND AUDITING
# ====================================================================

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
   

   
    

    
    
      
       

      

        
   
           
   
