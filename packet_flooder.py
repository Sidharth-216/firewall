import sys
import time
from scapy.all import Ether, IP, TCP, sendp
import netifaces

TARGET_IP = "192.168.2.1"  # Replace with the target IP address
def get_default_interface():
    gateways = netifaces.gateways()
    default_gateway = gateways.get('default')
    if default_gateway:
        return default_gateway[netifaces.AF_INET][1]
    return None

INTERFACE = get_default_interface()
if INTERFACE is None:
    print("Could not determine the default network interface.")
    sys.exit(1)
NUM_PACKETS = 100
DURATION = 5

def send_packets(target_ip, interface, num_packets, duration):
    packet = Ether() / IP(dst=target_ip) / TCP()
    end_time = time.time() + duration
    packet_count = 0

    while time.time() < end_time and packet_count < num_packets:
        sendp(packet, iface=interface)
        packet_count += 1

if __name__ == "__main__":
    if sys.version_info[0] < 3:
        print("This script requires Python 3.")
        sys.exit(1)

    send_packets(TARGET_IP, INTERFACE, NUM_PACKETS, DURATION)