from scapy.all import IP, UDP, ICMP, Raw, send
import random

def generate_random_ip():
    return ".".join(map(str, (random.randint(1, 255) for _ in range(4))))

def send_test_packets(target_ip, count=10):
    for _ in range(count):
        src_ip = generate_random_ip()  # Random fake source IP
        dst_ip = target_ip  # Target firewall IP
        
        # Randomly select a packet type
        packet_type = random.choice(["UDP", "ICMP", "Non-TCP"])
        
        if packet_type == "UDP":
            pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=random.randint(1024, 65535), dport=random.randint(1024, 65535)) / Raw(load="Dummy Data")
        
        elif packet_type == "ICMP":
            pkt = IP(src=src_ip, dst=dst_ip) / ICMP()
        
        else:  # Non-TCP (e.g., IGMP - Internet Group Management Protocol)
            pkt = IP(src=src_ip, dst=dst_ip, proto=2)  # Proto 2 = IGMP
        
        send(pkt, verbose=False)
        print(f"Sent {packet_type} packet: {src_ip} -> {dst_ip}")

if __name__ == "__main__":
    target_ip = input("Enter the target IP: ")
    send_test_packets(target_ip, count=20)  # Send 20 packets
