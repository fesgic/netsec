import logging
import os
import sys

logging.getLogger("scapy").setLevel(logging.CRITICAL)
from scapy.all import *


def packet_capture(pkt):
    pkt.show()
    wrpcap(file, pkts)


def permissions():
    os.system(f"chmod 777 {file}")

sniff(iface=interface, prn=packet_capture, store=0)
