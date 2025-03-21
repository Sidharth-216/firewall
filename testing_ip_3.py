from scapy.all import IP, TCP, ICMP, Raw, send

def send_nimda_packet(target_ip, target_port=80, source_ip="192.168.1.1", source_port=12345):
    packet = (
        IP(src=source_ip, dst=target_ip)
        / TCP(sport=source_port, dport=target_port)
        / Raw(load="GET /scripts/root.exe HTTP/1.0\r\nHost: example.com\r\n\r\n")
    )
    send(packet, verbose=False)
    print(f"Sent Nimda-like packet to {target_ip} from {source_ip}")

def send_icmp_packet(target_ip, source_ip="192.168.1.1"):
    packet = IP(src=source_ip, dst=target_ip) / ICMP() / "Dummy ICMP Packet"
    send(packet, verbose=False)
    print(f"Sent ICMP packet to {target_ip} from {source_ip}")

def send_mixed_ip_packet(target_ip, source_ip="192.168.1.1"):
    harmful_ip = "192.168.99.99"  # Example of a flagged/bad IP
    good_ip = "8.8.8.8"  # Example of a safe/good IP (Google DNS)

    packet_harmful = IP(src=source_ip, dst=target_ip) / TCP(dport=80) / Raw(load=f"Flagged IP: {harmful_ip}")
    packet_good = IP(src=source_ip, dst=target_ip) / TCP(dport=80) / Raw(load=f"Trusted IP: {good_ip}")

    send(packet_harmful, verbose=False)
    send(packet_good, verbose=False)
    
    print(f"Sent dummy harmful IP packet to {target_ip} with payload {harmful_ip}")
    print(f"Sent dummy good IP packet to {target_ip} with payload {good_ip}")

if __name__ == "__main__":
    target_ip = "192.168.1.1"  # Replace with actual target IP

    send_nimda_packet(target_ip)
    send_icmp_packet(target_ip)
    send_mixed_ip_packet(target_ip)
