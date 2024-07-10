from scapy.all import sniff, IP, TCP, UDP


def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        # Determine the protocol type and extract payload
        if proto == 6:  # TCP
            protocol = "TCP"
            payload = packet[TCP].payload
        elif proto == 17:  # UDP
            protocol = "UDP"
            payload = packet[UDP].payload
        else:
            protocol = "Other"
            payload = packet[IP].payload

        # Print packet information
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {protocol}")
        print(f"Payload: {bytes(payload)}")
        print("\n" + "-" * 50 + "\n")


def main():
    # Get the network interface to sniff on
    interface = input("Enter the network interface to sniff on (e.g., Ethernet, Wi-Fi): ")
    print(f"Sniffing on {interface}...")

    # Start sniffing
    sniff(iface=interface, prn=packet_callback, store=False)


if __name__ == "__main__":
    main()
