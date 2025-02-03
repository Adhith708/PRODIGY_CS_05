from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        # Print basic packet information
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}")

        # Check for TCP or UDP and print payload if available
        if TCP in packet:
            print("Protocol: TCP")
            if Raw in packet:
                print(f"Payload: {packet[Raw].load}")
        elif UDP in packet:
            print("Protocol: UDP")
            if Raw in packet:
                print(f"Payload: {packet[Raw].load}")

        print("-" * 50)

def start_sniffer(interface=None):
    print("Starting packet sniffer...")
    # Start sniffing packets
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    # You can specify the network interface to sniff on, e.g., 'eth0', 'wlan0'
    start_sniffer()
