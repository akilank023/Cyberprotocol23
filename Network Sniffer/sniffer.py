from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    print("\n--- Packet Captured ---")

    if packet.haslayer(IP):
        print(f"Source IP      : {packet[IP].src}")
        print(f"Destination IP : {packet[IP].dst}")
        print(f"Protocol       : {packet[IP].proto}")

    if packet.haslayer(TCP):
        print("Protocol Name  : TCP")
        print(f"Source Port    : {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")

    elif packet.haslayer(UDP):
        print("Protocol Name  : UDP")
        print(f"Source Port    : {packet[UDP].sport}")
        print(f"Destination Port: {packet[UDP].dport}")

    elif packet.haslayer(ICMP):
        print("Protocol Name  : ICMP")

    payload = bytes(packet.payload)
    print(f"Payload Length : {len(payload)} bytes")

sniff(prn=packet_callback, count=10)