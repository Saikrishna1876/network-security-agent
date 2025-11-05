# Network Security Agent

This project implements a network security agent with various detection and action capabilities to protect against common network threats.

## Features

- **ARP Spoofing Detection and Prevention:** Identifies and mitigates ARP spoofing attacks.
- **DDoS Detection:** Detects Distributed Denial of Service attacks.
- **DNS Spoofing Detection:** Identifies malicious DNS spoofing attempts.
- **Malware C2 Detection:** Detects communication with known malware Command and Control servers.
- **Phishing Detection:** Helps identify phishing attempts.
- **Blacklist Management:** Manages a blacklist of malicious entities.
- **Client Management:** Manages connected clients and their security status.

## Project Structure

- `actions/`: Contains scripts for taking action against detected threats (e.g., `arp_spoof_action.py`).
- `detectors/`: Houses various detection modules (e.g., `arp_monitor_all.py`, `ddos_detector.py`).
- `managers/`: Includes modules for managing clients and blacklists (e.g., `blacklist_manager.py`, `client_manager.py`).

## Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/network-security-agent.git
    cd network-security-agent
    ```

2.  **Install dependencies:**
    ```bash
    # Assuming Python and uv are installed
    uv pip install -r requirements.txt
    ```

3.  **Environment Variables:**
    Create a `.env` file based on `.env.example` and configure necessary environment variables.

## Usage

Further instructions on how to run and configure the agent will be provided here.