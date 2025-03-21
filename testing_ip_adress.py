import socket
import time

def test_firewall(target_ip, port=80):
    try:
        print(f"Testing firewall with IP: {target_ip}")
        
        # Create a TCP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)  # Set timeout to avoid hanging
        
        start_time = time.time()
        
        # Attempt to connect to the target IP
        result = s.connect_ex((target_ip, port))
        
        end_time = time.time()
        s.close()
        
        if result == 0:
            print(f"[ALERT] Connection to {target_ip} succeeded! Your firewall may not be blocking it.")
        else:
            print(f"[OK] Connection to {target_ip} blocked! Your firewall is working.")
        
        print(f"Time taken: {end_time - start_time:.2f} seconds\n")
        
    except Exception as e:
        print(f"Error: {e}")

# List of known blocked/bogon IPs for testing
dummy_ips = [
    # Blocked IPs (Bogon, Private, or Invalid IPs)
    "192.0.2.1", "203.0.113.1", "198.51.100.1", "10.255.255.255",
    "172.16.0.1", "172.31.255.255", "169.254.1.1", "100.64.0.1",
    "192.168.1.1", "192.168.255.255", "0.0.0.0", "255.255.255.255",
    "192.18.0.1", "198.18.0.1", "224.0.0.1", "240.0.0.1",
    "100.100.100.100", "198.19.255.255", "198.20.0.0", "198.51.100.255",
    
    # Allowed IPs (Public and reachable)
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "208.67.222.222",
    "208.67.220.220", "9.9.9.9", "8.26.56.26", "8.20.247.20", "64.6.64.6",
    "64.6.65.6", "4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4", "4.2.2.5",
    "4.2.2.6", "156.154.70.1", "156.154.71.1", "149.112.112.112",
    "149.112.112.112", "199.85.126.10", "8.26.56.26", "149.112.112.11",
    "9.9.9.9", "149.112.112.9", "185.228.168.9", "185.228.169.9",
    "45.90.28.9", "45.90.30.9", "94.140.14.14", "94.140.15.15",
    "185.222.222.222", "185.184.222.222", "76.76.19.19", "76.223.122.150"
]

for ip in dummy_ips:
    test_firewall(ip)
