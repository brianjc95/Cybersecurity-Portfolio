#Log Analyzer

# Step 4: Count failed attempts per IP

import sys
import time
import csv
import os
from datetime import datetime

def follow(file):
    file.seek(0, 2)
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.5)
            continue
        yield line

if len(sys.argv) < 2:
    print("Usage: python log_analyzer.py <logfile>")
    sys.exit()

log_file = sys.argv[1]
csv_file = "rate_based_report.csv"
csv_exists = os.path.isfile(csv_file)

if not csv_exists:
    with open(csv_file, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "IP Address", "Username", "Failed Attempts in Window", "Alert"])

# Dictionary: IP -> list of timestamps
ip_attempts = {}
THRESHOLD = 3           # Number of attempts to trigger alert
WINDOW_SECONDS = 60     # Time window in seconds

with open(log_file, "r") as file:
    loglines = follow(file)

    for line in loglines:
        if "Failed password" in line:
            parts = line.split()
            timestamp_str = " ".join(parts[0:3])
            ip = parts[-4]
            user = parts[8]

            timestamp_obj = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")

            if ip not in ip_attempts:
                ip_attempts[ip] = []

            ip_attempts[ip].append(timestamp_obj)

            # Remove old timestamps outside the window
            ip_attempts[ip] = [t for t in ip_attempts[ip] if (timestamp_obj - t).total_seconds() <= WINDOW_SECONDS]

            alert = ""
            if len(ip_attempts[ip]) > THRESHOLD:
                alert = "ALERT: Rapid failed attempts"
                print(f"[ALERT] {ip} has {len(ip_attempts[ip])} failed attempts in last {WINDOW_SECONDS} seconds!")

            print(f"[FAILED] {timestamp_str} - {ip} ({user}) attempt #{len(ip_attempts[ip])} {alert}")

            # Write to CSV
            with open(csv_file, "a", newline="") as file:
                writer = csv.writer(file)
                writer.writerow([timestamp_str, ip, user, len(ip_attempts[ip]), alert])