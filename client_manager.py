import csv
import os

CLIENTS_FILE = "clients.csv"


def load_clients():
    clients = {}
    if os.path.exists(CLIENTS_FILE):
        with open(CLIENTS_FILE, "r") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) == 2:
                    clients[row[0]] = row[1]
    return clients


def save_clients(clients):
    with open(CLIENTS_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        for ip, mac in clients.items():
            writer.writerow([ip, mac])


clients = load_clients()
