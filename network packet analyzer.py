from scapy.all import sniff, IP, TCP, UDP, Raw
from scapy.layers.http import HTTPRequest

def packet_callback(packet):
    """Callback function to process each captured packet."""
    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto

            print(f"\n[+] Packet Captured:")
            print(f"    Source IP: {src_ip}")
            print(f"    Destination IP: {dst_ip}")
            print(f"    Protocol: {protocol}")

            if TCP in packet:
                print("    TCP Packet")
            elif UDP in packet:
                print("    UDP Packet")
            
            if packet.haslayer(HTTPRequest):
                http_layer = packet[HTTPRequest]
                print(f"    HTTP Request: {http_layer.Host.decode()} {http_layer.Path.decode()}")
            
            if Raw in packet:
                print(f"    Payload: {packet[Raw].load}")
    except Exception as e:
        print(f"Error processing packet: {e}")

def start_sniffer(interface=None):
    """Start sniffing packets on the specified interface."""
    print("Starting packet sniffer...")
    print("Press Ctrl+C to stop.\n")
    sniff(iface=interface, prn=packet_callback, store=False)

if __name__ == "__main__":
    interface = input("Enter the network interface to sniff (or press Enter for default): ").strip()
    start_sniffer(interface if interface else None)
