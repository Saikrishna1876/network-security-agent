import scapy.all as scapy
from scapy.layers.http import HTTP, HTTPRequest

import os
from dotenv import load_dotenv
from urllib.parse import urlparse, parse_qs
import requests

load_dotenv()

# List of keywords commonly found in credential fields
CREDENTIAL_KEYWORDS = ["password", "username", "email", "login", "pass", "account"]


def is_suspicious_url(url):
    """
    Basic heuristic to check for suspicious URL patterns.
    This can be expanded with more sophisticated checks (e.g., typosquatting, IP in hostname).
    """
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    # Example: Check if hostname is an IP address (often used in phishing)
    if (
        hostname
        and all(part.isdigit() for part in hostname.split("."))
        and len(hostname.split(".")) == 4
    ):
        return True

    # Add more URL heuristics here if needed
    return False


def process_packet(packet):
    """
    Processes sniffed packets to detect potential phishing attempts.
    """
    if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
        # Check for HTTP POST requests
        try:
            http_request = scapy.HTTPRequest(packet[scapy.Raw].load)
            if http_request.Method == b"POST":
                url = http_request.Path.decode()
                host = http_request.Host.decode()
                full_url = f"http://{host}{url}"
                post_data = packet[scapy.Raw].load.decode(errors="ignore")

                print(f"[*] Detected HTTP POST to: {full_url}")

                # Check for suspicious URL
                if is_suspicious_url(full_url):
                    print(
                        f"[!!!] PHISHING ALERT: Suspicious URL detected in POST request: {full_url}"
                    )
                    url = os.getenv("NOTIFY_WEBHOOK_URL")
                    if url:
                        requests.post(
                            url,
                            data=f"PHISHING ALERT: Suspicious URL detected in POST request: {full_url}".encode(
                                encoding="utf-8"
                            ),
                        )

                # Parse POST data and check for credential patterns
                parsed_post_data = parse_qs(post_data)
                for field, values in parsed_post_data.items():
                    decoded_field = field.lower()
                    if any(keyword in decoded_field for keyword in CREDENTIAL_KEYWORDS):
                        print(
                            f"[!!!] PHISHING ALERT: Credential pattern '{decoded_field}' found in POST data to {full_url}. Values: {values}"
                        )
                        url = os.getenv("NOTIFY_WEBHOOK_URL")
                        if url:
                            requests.post(
                                url,
                                data=f"PHISHING ALERT: Credential pattern '{decoded_field}' found in POST data to {full_url}. Values: {values}".encode(
                                    encoding="utf-8"
                                ),
                            )

        except Exception as e:
            # Not an HTTP request or malformed HTTP
            pass


def sniff_http_traffic(interface):
    """
    Starts sniffing HTTP traffic on the specified interface.
    """
    print(f"[*] Starting phishing detector on interface {interface}...")
    # Load HTTP layer for Scapy to parse HTTP packets
    scapy.load_layer("http")

    # Bind HTTP layer to TCP ports 80 and 443 (for unencrypted HTTP and HTTPS, though HTTPS content will be encrypted)
    scapy.bind_layers(scapy.TCP, scapy.HTTP, dport=80)
    scapy.bind_layers(scapy.TCP, scapy.HTTP, sport=80)
    # For HTTPS, the content will be encrypted, so direct payload inspection won't work without SSL/TLS decryption.
    # We'll still sniff on 443 to at least detect POST requests, but won't be able to inspect payload.
    scapy.bind_layers(scapy.TCP, HTTP, dport=443)
    scapy.bind_layers(scapy.TCP, scapy.HTTP, sport=443)

    # Filter for TCP traffic on HTTP/HTTPS ports and use TCPSession for stream reassembly
    scapy.sniff(
        iface=interface,
        filter="tcp port 80 or tcp port 443",
        store=False,
        prn=process_packet,
        session=scapy.TCPSession,
    )


def run():
    interface = os.getenv("INTERFACE")
    if not interface:
        print(
            "Error: INTERFACE environment variable not set. Please set the INTERFACE environment variable (e.g., eth0, wlan0)."
        )
        return

    sniff_http_traffic(interface)


if __name__ == "__main__":
    run()
