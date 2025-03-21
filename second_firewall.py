from scapy.all import IP, TCP, UDP, DNS, DNSQR, send
from scapy.layers.inet import ICMP
import random
import time

# Define Good and Bad IPs
good_ips = ["192.168.1.10", "192.168.1.20", "10.0.0.5"]
bad_ips = ["203.0.113.5", "45.33.32.156", "185.220.101.1"]  # Common Tor, VPN, or flagged IPs

# Define Whitelist and Blacklist IPs
whitelist_ips = ["192.168.1.30", "192.168.1.40"]  # Replace with actual whitelisted IPs
blacklist_ips = ["203.0.113.5", "45.33.32.156"]  # Replace with actual blacklisted IPs

# Define Target IP
target_ip = "192.168.1.1"  # Replace with your firewall's testing machine

# Function to send benign traffic
def send_good_traffic():
    src_ip = random.choice(good_ips)
    packet = IP(src=src_ip, dst=target_ip) / TCP(dport=80, flags="S")  # Normal Web Request
    send(packet, verbose=False)
    print(f"[GOOD] Sent packet from {src_ip} to {target_ip}")

# Function to send harmful traffic
def send_bad_traffic():
    src_ip = random.choice(bad_ips)
    attack_type = random.choice(["port_scan", "dns_amplification", "flooding"])
    
    if attack_type == "port_scan":
        for port in range(20, 1025, 200):  # Simulates scanning open ports
            packet = IP(src=src_ip, dst=target_ip) / TCP(dport=port, flags="S")
            send(packet, verbose=False)
        print(f"[BAD] Port Scan Attack from {src_ip}")

    elif attack_type == "dns_amplification":
        packet = IP(src=src_ip, dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
        send(packet, verbose=False)
        print(f"[BAD] DNS Amplification Attempt from {src_ip}")

    elif attack_type == "flooding":
        for _ in range(5):
            packet = IP(src=src_ip, dst=target_ip) / TCP(dport=80, flags="S")
            send(packet, verbose=False)
        print(f"[BAD] SYN Flood Attack from {src_ip}")
# Initialize packet count dictionary
packet_count = {}
start_time = [time.time()]
THRESHOLD = 10  # Define a threshold for packet rate
dns_count = {}
PACKET_LIMIT = 5  # Define a packet limit for DNS requests
port_attempts = {}

# Function to block an IP
def block_ip(ip):
    print(f"[BLOCKED] {ip} - IP has been blocked")

# Packet processing function
def packet_callback(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src

    if src_ip in whitelist_ips:
        print(f"[ALLOWED] {src_ip} - Whitelisted")
        return

    if src_ip in blacklist_ips:
        block_ip(src_ip)
        return

    packet_count[src_ip] += 1
    current_time = time.time()
    time_interval = current_time - start_time[0]

    if time_interval >= 1:
        for ip, count in list(packet_count.items()):
            if count / time_interval > THRESHOLD:
                block_ip(ip)
            else:
                print(f"[MONITORING] {ip} - {count} packets/sec")
        packet_count.clear()
        start_time[0] = current_time
        if packet.haslayer(UDP):
            print(f"[UDP] {src_ip} - UDP packet detected")
            return

        if packet.haslayer(ICMP):
            print(f"[ICMP] {src_ip} - ICMP packet detected")
            return

        if not packet.haslayer(TCP):
            print(f"[NON-TCP] {src_ip} - Non-TCP packet detected")
            return
        if packet.haslayer(DNS) and packet[DNS].qr == 0:
            print(f"[DNS] {src_ip} - DNS request detected")
            dns_count[src_ip] += 1
            if dns_count[src_ip] > PACKET_LIMIT:
                block_ip(src_ip)
            return
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            port_attempts[src_ip].add(dst_port)
            if len(port_attempts[src_ip]) > 10:  # Threshold for multiple port attempts
                block_ip(src_ip)
            return
        '''if is_blocked_country(src_ip):
            block_ip(src_ip)
        return'''
    return
# Simulate Traffic
for _ in range(10):  # Send 10 packets randomly
    if random.random() < 0.6:  # 60% chance of good traffic, 40% bad
        send_good_traffic()
    else:
        send_bad_traffic()
    time.sleep(random.uniform(0.5, 2))  # Delay between packets

print("Test traffic generation completed.")
