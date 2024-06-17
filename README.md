# Simple Network Packet Sniffer with Scapy

This repository contains a simple Python script that demonstrates how to capture and analyze network traffic using the Scapy library.

## What it Does:

* Captures TCP packets on a specified network interface.
* Extracts source and destination IP addresses and ports.
* Prints the captured information to the console.

## Getting Started

1. **Install Kali Linux:** If you don't have Kali Linux installed, download and install it from [https://www.kali.org/](https://www.kali.org/).
2. **Install Python:** Kali Linux comes with Python pre-installed. If you need to update it, run:
    ```sh
    sudo apt update
    sudo apt install python3
    ```
3. **Install Scapy:** Install the Scapy library using pip:
    ```sh
    sudo pip install scapy
    ```
4. **Create a Python File:** Create a new file called `sniffer.py` in your desired directory (e.g., your Desktop):
    ```sh
    touch sniffer.py
    ```
5. **Copy and Paste the Code:** Copy the following code and paste it into your `sniffer.py` file:
    ```python
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
    ```
    ![Demo](https://github.com/Winnielegal/CodeAlpha_Basic_Network_Sniffer/blob/main/1.png)

6. **Run the Sniffer:** Open a terminal, navigate to your directory, and run the following command (replace `eth0` with your network interface name):
    ```sh
    sudo python sniffer.py eth0
    ```
    * **PS:** To check your network interface name, run the command:
    ```sh
    ifconfig
    ```

    ## Testing with Network Activity

1. *Generate Network Traffic:* While your sniffer is running, open another terminal and try a few things:
   * ping google.com
   * curl google.com
   * Open a web browser and visit a website.
2. *Observe Results:*  You should see the TCP connections for those activities printed in your sniffer terminal.

## Extending the Sniffer

* *Capture Other Protocols:* Modify the filter argument in the sniff function to capture other protocols (e.g., UDP, ICMP, DNS).
* *Log to a File:*  Save captured packets to a log file for later analysis.
* *Extract More Information:*  Add code to extract additional details from packets, such as timestamps, payload data, or protocol-specific information.

![Demo](https://github.com/Winnielegal/CodeAlpha_Basic_Network_Sniffer/blob/main/2.png)


## Additional Information:

* You'll need to run the script with `sudo` because packet sniffing requires root privileges.
* This script only captures TCP packets, but you can modify it to capture other protocols.

## Disclaimer:

* Use this tool responsibly. Packet sniffing can be illegal or unethical in some situations. Make sure you understand the laws and regulations in your area.
* Always test your sniffer in a controlled environment before using it on a production network.

## Let me know if you have any questions!
