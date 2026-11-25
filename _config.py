# ==================================================
# SECTION 1: IMPORTS AND CONFIGURATION
# ==================================================

from scapy.all import (
    sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, RadioTap,
    Dot11AssoResp, Dot11ReassoResp
)

import argparse
import csv
import json

