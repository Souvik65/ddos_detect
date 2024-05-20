from scapy.all import *
from collections import defaultdict
import time
import threading

# Configuration
MONITOR_INTERFACE = 'eth0','wlan0'  # Network interface to monitor
TIME_WINDOW = 60  # Time window in seconds to count requests
THRESHOLD = 100  # Number of requests considered unusual

# Initialize a dictionary to store the count of requests
request_count = defaultdict(int)

def packet_callback(packet):
    # Check if the packet is an ICMP echo request
    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet[ICMP].type == 8:
        if packet[IP].dst == target_ip:
            source_ip = packet[IP].src
            request_count[source_ip] += 1
            print(f"ICMP Echo Request from {source_ip}: Count = {request_count[source_ip]}")

def monitor_requests():
    # Capture packets in real-time
    sniff(iface=MONITOR_INTERFACE, prn=packet_callback, store=False, filter="icmp")

def detect_spike():
    while True:
        time.sleep(TIME_WINDOW)
        total_requests = sum(request_count.values())
        print(f"Total ICMP Echo Requests in last {TIME_WINDOW} seconds: {total_requests}")
        
        if total_requests > THRESHOLD:
            print(f"Unusual activity detected: {total_requests} ICMP Echo Requests in the last {TIME_WINDOW} seconds")

        # Reset the count for the next time window
        request_count.clear()

if __name__ == "__main__":
    # Get the target IP from user input
    target_ip = input("Enter the target IP address: ")

    # Run monitoring and detection in parallel
    monitor_thread = threading.Thread(target=monitor_requests)
    detect_thread = threading.Thread(target=detect_spike)

    monitor_thread.start()
    detect_thread.start()

    monitor_thread.join()
    detect_thread.join()
