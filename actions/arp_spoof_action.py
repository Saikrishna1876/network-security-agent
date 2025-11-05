import os
import requests
from managers.blacklist_manager import blacklist, save_blacklist
from dotenv import load_dotenv
load_dotenv()

def blacklist_mac(mac_address):
    if mac_address not in blacklist:
        blacklist.add(mac_address)
        save_blacklist(blacklist)
        requests.post(os.getenv("NOTIFY_WEBHOOK_URL"),
            data=f"A {mac_address} has been blacklisted.".encode(encoding='utf-8'))
        print(f"[!!!] Blacklisted MAC address: {mac_address}")
