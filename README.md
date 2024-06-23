# packet-sniffer-analyzer


Imports:

from scapy.all import sniff: Importing the sniff function from scapy.
from scapy.layers.inet import IP, TCP, UDP, ICMP: Importing the necessary layers to analyze IP, TCP, UDP, and ICMP packets.

packet_callback Function:

def packet_callback(packet): This function is called whenever a packet is captured.
It checks if the packet contains an IP layer and extracts relevant information like source and destination IP addresses.
It then checks for common protocols (TCP, UDP, ICMP) and extracts relevant information such as ports and payload.

Starting the Sniffer:

print("Starting packet sniffer..."): A message indicating that the packet sniffer is starting.
sniff(prn=packet_callback, store=0): Starts sniffing packets and calls the packet_callback function for each captured packet. The store=0 parameter indicates that packets should not be stored in memory.

First, ensure you have the scapy library installed. You can install it using pip:


```
pip install scapy
```
Here is the Python code for a simple packet sniffer:

python code from scapy.all import sniff from scapy.layers.inet import IP, TCP, UDP, ICMP

```
def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\n[+] New Packet: {ip_layer.src} -> {ip_layer.dst}")

        # Check for common protocols and display relevant information
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"Protocol: TCP | Source Port: {tcp_layer.sport} | Destination Port: {tcp_layer.dport}")
            print(f"Payload: {tcp_layer.payload}")

        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"Protocol: UDP | Source Port: {udp_layer.sport} | Destination Port: {udp_layer.dport}")
            print(f"Payload: {udp_layer.payload}")

        elif packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            print(f"Protocol: ICMP | Type: {icmp_layer.type} | Code: {icmp_layer.code}")

        else:
            print("Protocol: Other")

# Start sniffing
print("Starting packet sniffer...")
sniff(prn=packet_callback, store=0)

```
