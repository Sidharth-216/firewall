import os
import sys
import time
import smtplib
from collections import defaultdict
import threading
import ipaddress
from scapy.all import sniff, IP, TCP, UDP, ICMP, RawVal, Ether, sendp, DNS
from scapy.all import *
 # GeoIP Blocking (Country-based Blocking)
#import maxminddb

# Thresholds and configurations
THRESHOLD = 40
PACKET_LIMIT = 100
DURATION = 5
ALERT_EMAIL = "sidupatnaik216@gmail.com"
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587
SMTP_USER = "sidupatnaik216@gmail.com"
SMTP_PASS = "xxxxxxx"


packet_count = {}  # Ensure this is defined globally
# Ensure whitelist and blacklist files exist
for filename in ["whitelist.txt", "blacklist.txt"]:
    if not os.path.exists(filename):
        open(filename, "w").close()

# Read IPs from a file
def read_ip_file(filename):
    with open(filename, "r") as file:
        return {line.strip() for line in file}

# Log events
def log_event(message):
    log_folder = "logs"
    os.makedirs(log_folder, exist_ok=True)
    log_file = os.path.join(log_folder, f"log_{time.strftime('%Y-%m-%d')}.log")
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    with open(log_file, "a") as file:
        file.write(f"{timestamp} - {message}\n")

def tail_log(log_file, src_ip):
    try:
        with open(log_file, "r") as file:
            file.seek(0, os.SEEK_END)  # Move to the end of the file
            while True:
                line = file.readline()
                if not line:
                    break  # No new line, break
                if src_ip in line:
                    log_event(f"Alert from {log_file} for {src_ip}: {line.strip()}")
                    block_ip(src_ip)
    except Exception as e:
        log_event(f"Failed to read {log_file}: {e}")



# Send alert email
def send_alert_email(subject, message):
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, ALERT_EMAIL, f"Subject: {subject}\n\n{message}")
        server.quit()
    except Exception as e:
        log_event(f"Failed to send alert email: {e}")

# Check if an IP is already blocked
def is_already_blocked(ip):
    result = os.system(f"iptables -C INPUT -s {ip} -j DROP")
    if result == 0:
        print(f"[BLOCKED] {ip} - Already in firewall rules")
    return result == 0

# Block an IP using iptables
def block_ip(ip):
    if ip in blocked_ips or is_already_blocked(ip):
        return
    os.system(f"iptables -A INPUT -s {ip} -j DROP")
    log_event(f"Blocked IP: {ip}")
    print(f"[BLOCKED] {ip} - Added to firewall rules")
    threading.Thread(target=send_alert_email, args=("Firewall Alert", f"Blocked suspicious IP: {ip}")).start()
    blocked_ips.add(ip)


# Detect Nimda worm
def is_nimda_worm(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        try:
            payload = bytes(packet[TCP].payload).decode(errors="ignore")
            return "GET /scripts/root.exe" in payload
        except Exception:
            return False
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
            block_ip(src_ip)
            return

        if packet.haslayer(ICMP):
            print(f"[ICMP] {src_ip} - ICMP packet detected")
            block_ip(src_ip)
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

        if not packet.haslayer(TCP):
            print(f"[NON-TCP] {src_ip} - Non-TCP packet detected")
            return
    return False



# Detect Bogon IP addresses
def is_bogon_ip(ip):
    bogon_ranges = [
            "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
            "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
            "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
            "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32"
        ]
    for bogon in bogon_ranges:
        if ipaddress.ip_address(ip) in ipaddress.ip_network(bogon):
            return True
    return False
    
# Packet processing function
def packet_callback(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src

    if src_ip in whitelist_ips:
        print(f"[ALLOWED] {src_ip} - Whitelisted")
        return

    if src_ip in blacklist_ips or is_nimda_worm(packet):
        block_ip(src_ip)
        return


    
    '''if is_blocked_country(src_ip):
        block_ip(src_ip)
    return'''
    return
# Function to get country code from IP
'''def get_country_code(ip):
    try:
        response = geoip_reader.country(ip)
        return response.country.iso_code
    except Exception as e:
        log_event(f"GeoIP lookup failed for {ip}: {e}")
        return None'''

# Print all IPs being monitored
def print_monitored_ips():
    if not packet_count:
        print("No IPs are being monitored yet.")
    else:
        print("Currently monitored IPs:")
        for ip in packet_count.keys():
            print(ip)


# Schedule periodic printing of monitored IPs
def schedule_print_monitored_ips():
    while True:
        time.sleep(60)  # Print every 60 seconds
        print_monitored_ips()

# Start the thread for printing monitored IPs
threading.Thread(target=schedule_print_monitored_ips, daemon=True).start()

# Use Suricata or Snort for advanced signature-based detection
def detect_with_suricata(packet):
    tail_log("/var/log/suricata/fast.log", packet[IP].src)

def detect_with_snort(packet):
    tail_log("/var/log/snort/alert", packet[IP].src)

# Call Suricata and Snort detection functions inside packet_callback

# Auto-whitelist known safe subnets
whitelist_ips = read_ip_file("whitelist.txt")
safe_subnets = [
    "192.168.1.0/24",  # Example safe subnet
    "10.0.0.0/8",      # Another example safe subnet
]
for subnet in safe_subnets:
    for src_ip in whitelist_ips:
        if ipaddress.ip_address(src_ip) in ipaddress.ip_network(subnet):
            print(f"[ALLOWED] {src_ip} - Auto-whitelisted subnet {subnet}")


# Load GeoIP database
geoip_db_path = "/path/to/GeoLite2-Country.mmdb"

'''# Open the GeoIP2 database
# with maxminddb.open_database(geoip_db_path) as geoip_reader:
    # Example: Lookup an IP address
    response = geoip_reader.get('8.8.8.8')

    # Extract country name
    country = response.get('country', {}).get('names', {}).get('en', 'Unknown')

    print("Country:", country)'''

# List of blocked countries (ISO country codes)
blocked_countries = {"CN", "RU", "KP"}  # Example: China, Russia, North Korea

# Check if IP belongs to a blocked country
'''def is_blocked_country(ip):
    country_code = get_country_code(ip)
    if country_code in blocked_countries:
        log_event(f"Blocked country IP: {ip} ({country_code})")
        return True
    return False'''


 # Auto-remove blocked IPs after a cooldown period
COOLDOWN_PERIOD = 300  # 5 minutes

def unblock_ip(ip):
    if ip in blocked_ips:
        os.system(f"iptables -D INPUT -s {ip} -j DROP")
        log_event(f"Unblocked IP: {ip}")
        print(f"[UNBLOCKED] {ip} - Removed from firewall rules")
        blocked_ips.remove(ip)

def schedule_unblock(ip):
    time.sleep(COOLDOWN_PERIOD)
    unblock_ip(ip)

    # Schedule unblock for blocked IPs
    for ip in list(blocked_ips):
        if ip not in whitelist_ips and ip not in blacklist_ips:
            threading.Thread(target=schedule_unblock, args=(ip,)).start()

# Detect and mitigate TCP SYN Flood attacks using SYN cookies
def is_syn_flood(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        syn_count[packet[IP].src] += 1
        if syn_count[packet[IP].src] > SYN_THRESHOLD:
            return True
    return False

def mitigate_syn_flood(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        # Generate SYN cookie
        syn_cookie = os.urandom(16)
        # Send SYN-ACK with SYN cookie
        syn_ack = Ether(src=packet[Ether].dst, dst=packet[Ether].src) / \
                    IP(src=packet[IP].dst, dst=packet[IP].src) / \
                    TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, flags="SA", seq=RawVal(syn_cookie))
        sendp(syn_ack, verbose=False)
        log_event(f"SYN cookie sent to {packet[IP].src}")

# Initialize SYN flood detection variables
SYN_THRESHOLD = 100  # Example threshold for SYN packets
syn_count = defaultdict(int)

 # Update packet processing function to include SYN flood detection
def packet_callback(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src

    if src_ip in whitelist_ips:
        print(f"[ALLOWED] {src_ip} - Whitelisted")
        return

    if src_ip in blacklist_ips or is_nimda_worm(packet):
        block_ip(src_ip)
        return

    if is_syn_flood(packet):
        mitigate_syn_flood(packet)
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
        if packet.haslayer(TCP) and packet[TCP].flags == "S":
            syn_count[src_ip] += 1
            if syn_count[src_ip] > SYN_THRESHOLD:
                mitigate_syn_flood(packet)
                return


# Application Layer Filtering
def is_malicious_http(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        try:
            payload = bytes(packet[TCP].payload).decode(errors="ignore")
            if "malicious" in payload:  # Example check for malicious content
                return True
        except Exception as e:
            log_event(f"Failed to decode HTTP payload: {e}")
    return False

def is_malicious_dns(packet):
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        query = packet[DNS].qd.qname.decode(errors="ignore")
        if "malicious.com" in query:  # Example check for malicious domain
            return True
    return False

 # Update packet processing function to include application layer filtering
def packet_callback(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src

    if src_ip in whitelist_ips:
        print(f"[ALLOWED] {src_ip} - Whitelisted")
        return

    if src_ip in blacklist_ips or is_nimda_worm(packet):
        block_ip(src_ip)
        return

    if is_syn_flood(packet):
        mitigate_syn_flood(packet)
        return

    if is_malicious_http(packet) or is_malicious_dns(packet):
        block_ip(src_ip)
        return

    # Detect application layer protocols
    if packet.haslayer(TCP):
        if packet[TCP].dport in [80, 443]:  # HTTP, HTTPS
            print("[APPLICATION LAYER] HTTP/HTTPS Traffic Detected")
        elif packet[TCP].dport == 21:  # FTP
            print("[APPLICATION LAYER] FTP Traffic Detected")
        elif packet[TCP].dport in [25, 587, 465]:  # SMTP
            print("[APPLICATION LAYER] SMTP Traffic Detected")
    if packet.haslayer(DNS):  # DNS Queries
        print("[APPLICATION LAYER] DNS Query Detected")

    inspect_payload(packet)  # Perform DPI
    detect_with_suricata(packet)
    detect_with_snort(packet)

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
# Deep Packet Inspection (DPI) for Malicious Payloads
def inspect_payload(packet):
    try:
        eth = packet.getlayer(Ether)
        if not packet.haslayer(IP):
            return
        
        ip = eth.data
        if packet.haslayer(TCP):
            payload = bytes(packet[TCP].payload)
            if b"malicious" in payload:  # Example check for malicious content
                log_event(f"Malicious payload detected from {packet[IP].src}")
            block_ip(packet[IP].src)
    except Exception as e:
        log_event(f"Failed to inspect payload: {e}")

# Update packet processing function to include DPI
def packet_callback(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src

    if src_ip in whitelist_ips:
        print(f"[ALLOWED] {src_ip} - Whitelisted")
        return

    if src_ip in blacklist_ips or is_nimda_worm(packet):
        block_ip(src_ip)
        return

    if is_syn_flood(packet):
        mitigate_syn_flood(packet)
        return

    inspect_payload(packet)  # Perform DPI

    inspect_payload(packet)  # Perform DPI
    detect_with_suricata(packet)
    detect_with_snort(packet)
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
                                   
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script requires root privileges.")
        sys.exit(1)

    whitelist_ips = read_ip_file("whitelist.txt")
    blacklist_ips = read_ip_file("blacklist.txt")
    packet_count = defaultdict(int)
    dns_count = defaultdict(int)
    port_attempts = defaultdict(set)
    start_time = [time.time()]
    blocked_ips = set()

    print("Firewall is active. Monitoring network traffic... ")
    sniff(filter="ip", prn=packet_callback)
