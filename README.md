# Scapy Scripts

## basic.py

This script provides a comprehensive analysis of a pcapng file to help understand network traffic patterns, identify unique devices, and detect potential suspicious activities. You get your pcapng file through a wireshark capture.

### Features

- **Unique MAC Address Identification:** Lists all unique MAC addresses detected in the traffic.

- **Frequency Analysis:** Displays the most active MAC addresses based on packet frequency.

- **Packet Size Analysis:** Calculates the average, minimum, and maximum sizes of packets.

- **Packet Timing Analysis:** Computes the average, minimum, and maximum intervals between consecutive packets.

- **Content Analysis**: Identifies unencrypted HTTP traffic.

- **Suspicious Activity Detection:** Flags IP addresses that exceed a certain threshold of packet activity.

### Usage
Ensure you have the required Python packages installed:

Copy code

`pip install scapy`

Provide the path to your pcapng file in `basic.py`.

`packets = rdpcap('/Users/macabe/Desktop/home.pcapng')`

Run the script.

`python3 basic.py`

Review the output for insights into your network traffic.


### Notes
The threshold for suspicious activity detection is currently set at 1000 packets. This can be adjusted based on the user's requirements. The assumption is the capture is just a few seconds.

### Future Enhancements
- Integration with GeoIP databases for geographical location insights.

- Visualization of traffic patterns.

- Deep packet inspection for further analysis.