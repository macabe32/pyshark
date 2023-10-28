from collections import Counter
import pyshark
# INITIAL SETUP
unique_mac_addresses = set()
mac_counter = Counter()
packet_sizes = []
packet_timestamps = []
http_traffic_found = False
ip_counter = Counter()

cap = pyshark.FileCapture('/Users/macabe/Desktop/home.pcapng')

# SINGLE PASS THROUGH PACKETS
for packet in cap:
    try:
        # MAC Address Analysis
        if "ETH" in packet:
            src_mac = packet.eth.src
            dst_mac = packet.eth.dst
            unique_mac_addresses.add(src_mac)
            unique_mac_addresses.add(dst_mac)
            mac_counter[src_mac] += 1
            mac_counter[dst_mac] += 1

        # Packet Size Analysis
        size = int(packet.length)
        packet_sizes.append(size)

        # Packet Timing Analysis
        timestamp = float(packet.sniff_timestamp)
        packet_timestamps.append(timestamp)

        # Content Analysis
        if "HTTP" in packet:
            http_traffic_found = True

        # Suspicious Activity
        if "IP" in packet:
            src_ip = packet.ip.src
            ip_counter[src_ip] += 1

    except Exception as e:
        print(f"Error processing packet: {e}")

# POST-PROCESSING

# Frequency Analysis
top_mac_addresses = mac_counter.most_common(10)

# Packet Size Analysis (Continued)
avg_size = sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0
min_size = min(packet_sizes) if packet_sizes else 0
max_size = max(packet_sizes) if packet_sizes else 0

# Packet Timing Analysis (Continued)
packet_intervals = [packet_timestamps[i] - packet_timestamps[i-1] for i in range(1, len(packet_timestamps))]
avg_interval = sum(packet_intervals) / len(packet_intervals) if packet_intervals else 0
min_interval = min(packet_intervals) if packet_intervals else 0
max_interval = max(packet_intervals) if packet_intervals else 0

# Suspicious Activity Analysis (Continued)
threshold = 1000
suspicious_ips = [ip for ip, count in ip_counter.items() if count > threshold]

# OUTPUT
print(f"Number of unique MAC addresses: {len(unique_mac_addresses)}")
print("Unique MAC addresses:")
for mac in unique_mac_addresses:
    print(mac)

print("\nTop 10 most active MAC addresses:")
for mac, count in top_mac_addresses:
    print(f"MAC Address: {mac} - Count: {count}")

print(f"\nAverage Packet Size: {avg_size:.2f} bytes")
print(f"Minimum Packet Size: {min_size} bytes")
print(f"Maximum Packet Size: {max_size} bytes")

print(f"\nAverage Packet Interval: {avg_interval:.6f} seconds")
print(f"Minimum Packet Interval: {min_interval:.6f} seconds")
print(f"Maximum Packet Interval: {max_interval:.6f} seconds")

if not http_traffic_found:
    print("\nThere is no unencrypted traffic.")

if suspicious_ips:
    print(f"\nSuspicious IP addresses (over {threshold} packets): {', '.join(suspicious_ips)}")
else:
    print("\nThere is no suspicious activity.")

