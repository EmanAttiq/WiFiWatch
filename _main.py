# ==================================================
# SECTION 6: RESULTS AND PROGRAM EXECUTION
# ==================================================

from .section1_config import *
from . import section2_data as state
from .section2_data import access_points, clients, security_audits
from .section3_packet import run_live_capture
from .section4_security import print_security_summary
from .section5_analysis import (
    detect_rogue_access_points, print_rogue_report,
    load_airodump_csv, print_channel_analysis, analyze_channels
)

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
        if not state.load_baseline(args.baseline):
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

