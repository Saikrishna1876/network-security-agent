import csv
import os

BLACKLIST_FILE = "blacklist.csv"


def load_blacklist():
    blacklist = set()
    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, "r") as f:
            reader = csv.reader(f)
            for row in reader:
                if row:
                    blacklist.add(row[0])
    return blacklist


def save_blacklist(blacklist):
    with open(BLACKLIST_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        for mac in blacklist:
            writer.writerow([mac])


blacklist = load_blacklist()
