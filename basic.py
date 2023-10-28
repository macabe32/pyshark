from scapy.all import rdpcap
from collections import Counter
import logging

# Suppress Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Load the pcapng file
packets = rdpcap('/Users/macabe/Desktop/home.pcapng')

# Unique MAC Address Identification
unique_mac_addresses = set()
for packet in packets:
    if packet.haslayer('Ether'):
        src_mac = packet['Ether'].src
        dst_mac = packet['Ether'].dst
        unique_mac_addresses.add(src_mac)
        unique_mac_addresses.add(dst_mac)

# Frequency Analysis of MAC Addresses
mac_counter = Counter()
for packet in packets:
    if packet.haslayer('Ether'):
        src_mac = packet['Ether'].src
        dst_mac = packet['Ether'].dst
        mac_counter[src_mac] += 1
        mac_counter[dst_mac] += 1

# Packet Size Analysis
packet_sizes = [len(packet) for packet in packets]

# Suspicious IP Detection based on Packet Count
ip_counter = Counter()
for packet in packets:
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        ip_counter[src_ip] += 1

threshold = 1000
suspicious_ips = [ip for ip, count in ip_counter.items() if count > threshold]

# Output Results

# Unique MAC Addresses
print(f"Number of unique MAC addresses: {len(unique_mac_addresses)}")
print("\nUnique MAC addresses:")
for mac in unique_mac_addresses:
    print(mac)

# Top MAC Addresses
print("\nTop MAC addresses by packet count:")
for mac, count in mac_counter.most_common(10):
    print(f"{mac}: {count} packets")

# Packet Size Analysis
avg_size = sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0
min_size = min(packet_sizes) if packet_sizes else 0
max_size = max(packet_sizes) if packet_sizes else 0

print(f"\nAverage packet size: {avg_size:.2f} bytes")
print(f"Minimum packet size: {min_size} bytes")
print(f"Maximum packet size: {max_size} bytes")

# Suspicious IPs
if suspicious_ips:
    print("\nSuspicious IPs (based on packet count threshold of 1000):")
    for ip in suspicious_ips:
        print(f"{ip}: {ip_counter[ip]} packets")
else:
    print("\nNo suspicious IPs detected based on the threshold.")
