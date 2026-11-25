# ====================================================================
# ROGUE ACCESS POINT DETECTION
# ====================================================================

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
