from scapy.all import sniff, srp, get_if_addr, Ether, ARP
import os
import ipaddress
from dotenv import load_dotenv
import csv
import datetime
import requests

load_dotenv()

PACKET_LOG_FILE = "packet_log.csv"

# Dictionary to store known IP-MAC mappings
from managers.client_manager import clients, save_clients
from actions.arp_spoof_action import blacklist_mac


def log_packet_metadata(timestamp, src_mac, dst_mac, src_ip, dst_ip, packet_type):
    with open(PACKET_LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        # Write header if file is empty
        if f.tell() == 0:
            writer.writerow(
                [
                    "Timestamp",
                    "Source MAC",
                    "Destination MAC",
                    "Source IP",
                    "Destination IP",
                    "Packet Type",
                ]
            )
        writer.writerow([timestamp, src_mac, dst_mac, src_ip, dst_ip, packet_type])


def get_network_range(interface):
    """
    Determines the network range (e.g., '192.168.1.0/24') for a given interface.
    """
    try:
        ip_address = get_if_addr(interface)
        # Assuming a /24 subnet for simplicity. This might need adjustment for specific network configurations.
        # A more robust solution would involve parsing system network configuration or using a library like `netifaces`.
        network = ipaddress.ip_network(f"{ip_address}/24", strict=False)
        return str(network)
    except Exception as e:
        print(f"Error getting network range for interface {interface}: {e}")
        return None


def scan_network(ip_range, interface):
    """
    Scans the network for active devices and populates the clients dictionary.
    """
    print(f"[*] Scanning network {ip_range} on interface {interface}...")
    try:
        # Use arping to discover active hosts
        ans, unans = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range),
            timeout=2,
            verbose=False,
            iface=interface,
        )
        for sent, received in ans:
            clients[received.psrc] = received.hwsrc
            save_clients(clients)
            print(f"    Found: {received.psrc} -> {received.hwsrc}")
        print(f"[*] Network scan complete. Found {len(clients)} devices.")
    except Exception as e:
        print(f"Error during network scan: {e}")


def get_mac_from_known_clients(ip: str) -> str | None:
    """
    Retrieves the MAC address for a given IP from the known clients dictionary.
    """
    return clients.get(ip)


def process_sniffed_packet(packet):
    """
    Processes sniffed packets to detect ARP spoofing and logs metadata.
    """
    timestamp = datetime.datetime.now().isoformat()
    src_mac = None
    dst_mac = None
    src_ip = None
    dst_ip = None
    packet_type = "Unknown"

    if packet.haslayer(Ether):
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        packet_type = "Ethernet"

    if packet.haslayer(ARP):
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
        packet_type = "ARP"

        log_packet_metadata(timestamp, src_mac, dst_mac, src_ip, dst_ip, packet_type)

        if packet[ARP].op == 2:  # ARP response (is-at)
            sender_ip = packet[ARP].psrc
            response_mac = packet[ARP].hwsrc

            if sender_ip in clients:
                real_mac = get_mac_from_known_clients(sender_ip)
                if real_mac != response_mac:
                    print(
                        f"[!!!] ARP SPOOFING DETECTED! {sender_ip} is at {response_mac}, but should be {real_mac}"
                    )
                    blacklist_mac(response_mac)
                # else:
                #     print(f"[*] {sender_ip} -> {response_mac} (OK)")
            else:
                print(
                    f"[?] Unknown device {sender_ip} responded with MAC {response_mac}. Potential new device or attack."
                )
                url = os.getenv("NOTIFY_WEBHOOK_URL")
                if url:
                    requests.post(
                        url,
                        data=f"Potential new device or attack from {sender_ip} with MAC {response_mac}".encode(
                            encoding="utf-8"
                        ),
                    )
                clients[sender_ip] = response_mac
                save_clients(clients)


def start_sniffing(interface):
    """
    Starts sniffing packets on the specified interface.
    """
    print(f"[*] Starting ARP monitor on interface {interface}...")
    sniff(iface=interface, store=False, prn=process_sniffed_packet)


def run():
    interface = os.getenv("INTERFACE")
    if not interface:
        print("Error: INTERFACE environment variable not set.")
        return

    network_range = get_network_range(interface)
    if not network_range:
        return

    scan_network(network_range, interface)
    start_sniffing(interface)


if __name__ == "__main__":
    run()
