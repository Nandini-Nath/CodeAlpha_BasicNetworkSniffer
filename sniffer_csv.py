from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import datetime
import csv
import json
from collections import Counter
from rich.console import Console
from rich.table import Table

console = Console()

CSV_FILE = "pro_captured_packets.csv"
JSON_FILE = "pro_captured_packets.json"

# Global counter for live statistics
protocol_counter = Counter()

# Prepare CSV headers
with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow([
        "Time", "Source IP", "Destination IP", "Protocol",
        "Source Port", "Destination Port", "Payload"
    ])

def packet_callback(packet):
    time_now = str(datetime.datetime.now())
    ip_src = ip_dst = protocol = sport = dport = payload = ""

    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "Other"

        if Raw in packet:
            try:
                payload = packet[Raw].load.decode(errors="ignore")[:80]
            except:
                payload = "[Binary/Encrypted Data]"

        # Update counter
        protocol_counter[protocol] += 1

        # Save to CSV
        with open(CSV_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([time_now, ip_src, ip_dst, protocol, sport, dport, payload])

        # Save to JSON
        with open(JSON_FILE, "a", encoding="utf-8") as f:
            json.dump({
                "time": time_now,
                "src": ip_src,
                "dst": ip_dst,
                "protocol": protocol,
                "sport": sport,
                "dport": dport,
                "payload": payload
            }, f)
            f.write("\n")

        # Pretty console output
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Time", style="dim", width=20)
        table.add_column("Source")
        table.add_column("Destination")
        table.add_column("Proto")
        table.add_column("Payload", style="green")

        table.add_row(time_now, f"{ip_src}:{sport}", f"{ip_dst}:{dport}", protocol, payload or "N/A")
        console.print(table)

        # Show live protocol stats
        console.print(f"[cyan]Live Protocol Stats:[/cyan] {dict(protocol_counter)}\n")

def main():
    console.print("[bold yellow][*] Starting Advanced Packet Sniffer...[/bold yellow]")
    console.print(f"[*] Saving packets to {CSV_FILE} and {JSON_FILE}")
    console.print("[*] Press Ctrl+C to stop.\n")

    try:
        sniff(prn=packet_callback, store=False)
    except KeyboardInterrupt:
        console.print("\n[red][*] Stopping packet sniffer... Goodbye![/red]")

if __name__ == "__main__":
    main()
