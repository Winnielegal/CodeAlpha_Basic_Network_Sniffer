import sys
from scapy.all import *

# Function to handle each packet
def handle_packet(packet):
    # Check if the packet contains TCP layer
    if packet.haslayer(TCP):
        # Extract source and destination IP addresses
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        # Extract source and destination ports
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        # Print packet information (or write to log file)
        print(f"TCP Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

# Main function to start packet sniffing
def main(interface):
    try:
        # Start packet sniffing on specified interface with filtering
        sniff(iface=interface, prn=handle_packet, filter="tcp", store=0) 
    except KeyboardInterrupt:
        sys.exit(0)

# Check if the script is being run directly
if __name__ == "__main__":
    # Check if the correct number of arguments is provided
    if len(sys.argv) < 2:
        print("Usage: python sniffer.py <interface>")
        sys.exit(1)
    # Call the main function with the specified interface
    main(sys.argv[1])
