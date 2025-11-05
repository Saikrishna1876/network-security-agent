import scapy.all as scapy
import os
import time
from collections import defaultdict
from dotenv import load_dotenv
import dns.resolver  # For querying a trusted DNS server

load_dotenv()

# Dictionary to store legitimate DNS responses (domain -> IP)
legitimate_dns_responses = {}

# Trusted DNS server for verification
TRUSTED_DNS_SERVER = os.getenv("TRUSTED_DNS_SERVER", "8.8.8.8")


def get_legitimate_ip(domain):
    """
    Queries a trusted DNS server to get the legitimate IP address for a domain.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [TRUSTED_DNS_SERVER]
        answers = resolver.resolve(domain, "A")
        return str(answers[0])
    except Exception as e:
        print(f"Error querying trusted DNS for {domain}: {e}")
        return None


def process_dns_packet(packet):
    """
    Processes sniffed packets to detect DNS spoofing.
    """
    if packet.haslayer(scapy.DNS) and packet.qr == 1:  # DNS Response
        # Check if there are answers in the DNS response
        if packet.an:
            for i in range(packet.ancount):
                dns_record = packet.an[i]
                if dns_record.type == 1:  # A record (IPv4 address)
                    domain = dns_record.rrname.decode().strip(".")
                    resolved_ip = dns_record.rdata

                    if domain not in legitimate_dns_responses:
                        # First time seeing this domain, verify with trusted DNS
                        trusted_ip = get_legitimate_ip(domain)
                        if trusted_ip:
                            legitimate_dns_responses[domain] = trusted_ip
                            if resolved_ip != trusted_ip:
                                print(
                                    f"[!!!] DNS SPOOFING DETECTED! Domain: {domain}, Reported IP: {resolved_ip}, Legitimate IP: {trusted_ip}"
                                )
                            else:
                                print(
                                    f"[*] Legitimate DNS response for {domain}: {resolved_ip}"
                                )
                        else:
                            print(
                                f"[?] Could not verify {domain} with trusted DNS. Reported IP: {resolved_ip}"
                            )
                    else:
                        # Compare with known legitimate IP
                        trusted_ip = legitimate_dns_responses[domain]
                        if resolved_ip != trusted_ip:
                            print(
                                f"[!!!] DNS SPOOFING DETECTED! Domain: {domain}, Reported IP: {resolved_ip}, Legitimate IP: {trusted_ip}"
                            )
                        # else:
                        #     print(f"[*] Legitimate DNS response for {domain}: {resolved_ip}")


def sniff_dns_traffic(interface):
    """
    Starts sniffing DNS traffic on the specified interface.
    """
    print(f"[*] Starting DNS spoofing detector on interface {interface}...")
    # Filter for UDP port 53 (DNS)
    scapy.sniff(
        iface=interface, filter="udp port 53", store=False, prn=process_dns_packet
    )


if __name__ == "__main__":
    interface = os.getenv("INTERFACE")
    if not interface:
        print("Error: INTERFACE environment variable not set.")
        exit(1)

    sniff_dns_traffic(interface)
