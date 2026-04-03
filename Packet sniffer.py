import csv
import os
import time
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, TCP, IP

# -------------------
# Configuration
# -------------------
CSV_FILE = "packet_report.csv"
THRESHOLD = 5         # packets from same IP in time window to trigger alert
WINDOW_SECONDS = 10   # seconds for rate-based detection

# -------------------
# Data Structures
# -------------------
ip_packets = defaultdict(list)          # Track packet timestamps per IP
last_alert_time = defaultdict(lambda: 0)  # Track last alert time per IP

# -------------------
# Initialize CSV
# -------------------
if not os.path.isfile(CSV_FILE):
    with open(CSV_FILE, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol", "Alert"])

# -------------------
# Packet Processing
# -------------------
def process_packet(packet):
    if TCP in packet and IP in packet:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        protocol = "TCP"
        alert = ""

        # Track packet timestamps
        now = time.time()
        ip_packets[src_ip].append(now)
        # Remove timestamps outside window
        ip_packets[src_ip] = [t for t in ip_packets[src_ip] if now - t <= WINDOW_SECONDS]

        # Rate-limited alert
        if len(ip_packets[src_ip]) > THRESHOLD:
            if now - last_alert_time[src_ip] > WINDOW_SECONDS:
                alert = f"ALERT: {len(ip_packets[src_ip])} packets in {WINDOW_SECONDS} sec"
                print(f"[ALERT] {src_ip} -> {dst_ip} ({len(ip_packets[src_ip])} packets in {WINDOW_SECONDS} sec)")
                last_alert_time[src_ip] = now

        # Write all packets to CSV (even if no alert)
        with open(CSV_FILE, "a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([timestamp, src_ip, dst_ip, src_port, dst_port, protocol, alert])

# -------------------
# Start Sniffing
# -------------------
print("Starting packet capture... (Press Ctrl+C to stop)")
sniff(prn=process_packet, store=False)