from scapy.all import *
from collections import defaultdict
import time
import threading

# Configuration
TIME_WINDOW = 60  # Time window in seconds to count requests
HTTP_THRESHOLD = 100  # Number of HTTP requests considered unusual
ICMP_THRESHOLD = 100  # Number of ICMP requests considered unusual

# Initialize dictionaries to store the count of requests
http_request_count = defaultdict(int)
icmp_request_count = defaultdict(int)

def get_valid_interface():
    interfaces = get_if_list()
    print("Available network interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i}: {iface}")
    
    while True:
        try:
            iface_index = int(input("Enter the number of the network interface to monitor: "))
            if 0 <= iface_index < len(interfaces):
                return interfaces[iface_index]
            else:
                print("Invalid number. Please choose from the available interfaces.")
        except ValueError:
            print("Invalid input. Please enter a number corresponding to the interface.")

def packet_callback(packet):
    if packet.haslayer(IP):
        if packet.haslayer(ICMP) and packet[ICMP].type == 8:
            # ICMP echo request
            if packet[IP].dst == target_ip:
                source_ip = packet[IP].src
                icmp_request_count[source_ip] += 1
                print(f"ICMP Echo Request from {source_ip}: Count = {icmp_request_count[source_ip]}")
        elif packet.haslayer(TCP) and packet.haslayer(Raw):
            try:
                http_payload = packet[Raw].load.decode('utf-8')
                if 'Host: ' + target_website in http_payload:
                    source_ip = packet[IP].src
                    http_request_count[source_ip] += 1
                    print(f"HTTP Request from {source_ip}: Count = {http_request_count[source_ip]}")
            except UnicodeDecodeError:
                pass  # Ignore packets that can't be decoded as HTTP

def monitor_requests():
    # Capture packets in real-time
    sniff(iface=MONITOR_INTERFACE, prn=packet_callback, store=False, filter="ip")

def detect_spike():
    while True:
        time.sleep(TIME_WINDOW)
        
        total_http_requests = sum(http_request_count.values())
        total_icmp_requests = sum(icmp_request_count.values())

        print(f"Total HTTP Requests in last {TIME_WINDOW} seconds: {total_http_requests}")
        print(f"Total ICMP Echo Requests in last {TIME_WINDOW} seconds: {total_icmp_requests}")

        if total_http_requests > HTTP_THRESHOLD:
            print(f"Unusual HTTP activity detected: {total_http_requests} HTTP requests in the last {TIME_WINDOW} seconds")

        if total_icmp_requests > ICMP_THRESHOLD:
            print(f"Unusual ICMP activity detected: {total_icmp_requests} ICMP Echo Requests in the last {TIME_WINDOW} seconds")

        # Reset the counts for the next time window
        http_request_count.clear()
        icmp_request_count.clear()

if __name__ == "__main__":
    # Get the target IP and network interface from user input
    target_ip = input("Enter the target IP address: ")
    target_website = input("Enter the target website domain (e.g., example.com): ")
    MONITOR_INTERFACE = get_valid_interface()

    # Run monitoring and detection in parallel
    monitor_thread = threading.Thread(target=monitor_requests)
    detect_thread = threading.Thread(target=detect_spike)

    monitor_thread.start()
    detect_thread.start()

    monitor_thread.join()
    detect_thread.join()
