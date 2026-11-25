WiFiWatch - Modular Files

The original script is separated into six section modules:

1. section1_config.py       Imports and configuration
2. section2_data.py         Shared data structures and baseline initialization
3. section3_packet.py       Wireless packet collection and parsing
4. section4_security.py     Wireless security detection
5. section5_analysis.py     Wireless network analysis and CSV loading
6. section6_main.py         Reports and program execution

main.py is the entry point.

Run from the directory containing the wifiwatch_project folder:
    python -m wifiwatch_project.main --help

The project requires Scapy:
    python -m pip install scapy

Live capture may require suitable wireless-interface configuration and
operating-system permissions. Use monitoring only on networks you own or
are authorized to assess.
