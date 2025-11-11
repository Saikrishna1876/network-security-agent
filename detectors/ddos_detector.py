import scapy.all as scapy
import os
import time
import threading
from collections import defaultdict
from dotenv import load_dotenv
import requests

load_dotenv()

# Configuration for DDoS detection
PACKET_THRESHOLD = 1000  # Number of packets per second to trigger an alert
TIME_WINDOW = 1  # Time window in seconds for packet counting
SYN_THRESHOLD = 500  # Number of SYN packets per second to trigger a SYN flood alert

# Global variables for packet counting
packet_counts = defaultdict(int)
syn_counts = defaultdict(int)
start_time = time.time()


def process_packet(packet):
    global start_time, packet_counts, syn_counts

    current_time = time.time()
    if current_time - start_time > TIME_WINDOW:
        # Reset counts and check for alerts
        for ip, count in packet_counts.items():
            if count > PACKET_THRESHOLD:
                print(
                    f"[!!!] DDoS Alert: High traffic detected to {ip} - {count} packets in {TIME_WINDOW}s"
                )
                url = os.getenv("NOTIFY_WEBHOOK_URL")
                if url:
                    requests.post(
                        url,
                        data=f"DDoS Alert: High traffic detected to {ip} - {count} packets in {TIME_WINDOW}s".encode(
                            encoding="utf-8"
                        ),
                    )

        for ip, count in syn_counts.items():
            if count > SYN_THRESHOLD:
                print(
                    f"[!!!] SYN Flood Alert: High SYN packet rate to {ip} - {count} SYN packets in {TIME_WINDOW}s"
                )
                url = os.getenv("NOTIFY_WEBHOOK_URL")
                if url:
                    requests.post(
                        url,
                        data=f"SYN Flood Alert: High SYN packet rate to {ip} - {count} SYN packets in {TIME_WINDOW}s".encode(
                            encoding="utf-8"
                        ),
                    )

        packet_counts = defaultdict(int)
        syn_counts = defaultdict(int)
        start_time = current_time

    # Increment packet count for destination IP
    if packet.haslayer(scapy.IP):
        dest_ip = packet[scapy.IP].dst
        packet_counts[dest_ip] += 1

        # Check for SYN packets
        if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == "S":
            syn_counts[dest_ip] += 1


def sniff_traffic(interface, stop_event):
    print(f"[*] Starting DDoS detector on interface {interface}...")
    scapy.sniff(
        iface=interface,
        store=False,
        prn=process_packet,
        stop_filter=lambda x: stop_event.is_set(),
    )


def run(stop_event):
    interface = os.getenv("INTERFACE")
    if not interface:
        print("Error: INTERFACE environment variable not set.")
        return

    sniff_traffic(interface, stop_event)


if __name__ == "__main__":
    stop_event = threading.Event()
    run(stop_event)
