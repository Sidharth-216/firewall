from scapy.all import IP, ICMP, send

def send_icmp_packet(target_ip, source_ip="192.168.1.1"):
    packet = IP(src=source_ip, dst=target_ip) / ICMP() / "Dummy ICMP Packet"
    send(packet, verbose=False)
    print(f"Sent ICMP packet to {target_ip} from {source_ip}")

if __name__ == "__main__":
    target_ip = "192.168.1.1"  # Replace with the target IP address
    send_icmp_packet(target_ip)
