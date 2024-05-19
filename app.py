from scapy.all import *
from collections import defaultdict
import time
import threading

# Configuration
MONITOR_INTERFACE = 'eth0'  # Network interface to monitor
TIME_WINDOW = 60  # Time window in seconds to count requests
THRESHOLD = 100  # Number of requests considered unusual

# Initialize a dictionary to store the count of requests
request_count = defaultdict(int)

def packet_callback(packet):
    # Check if the packet has a HTTP request
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
        try:
            http_payload = packet[Raw].load.decode('utf-8')
            if 'Host: ' + target_website in http_payload:
                source_ip = packet[IP].src
                request_count[source_ip] += 1
                print(f"Request from {source_ip}: Count = {request_count[source_ip]}")
        except UnicodeDecodeError:
            pass  # Ignore packets that can't be decoded as HTTP

def monitor_requests():
    # Capture packets in real-time
    sniff(iface=MONITOR_INTERFACE, prn=packet_callback, store=False, filter="tcp port 80")

def detect_spike():
    while True:
        time.sleep(TIME_WINDOW)
        total_requests = sum(request_count.values())
        print(f"Total requests in last {TIME_WINDOW} seconds: {total_requests}")
        
        if total_requests > THRESHOLD:
            print(f"Unusual activity detected: {total_requests} HTTP requests in the last {TIME_WINDOW} seconds")

        # Reset the count for the next time window
        request_count.clear()

if __name__ == "__main__":

    print('''
    **********************************************************************
    *     _     _   _   ___   _   _ __   __ __  __   ___   _   _   ____  * 
    *    / \   | \ | | / _ \ | \ | |\ \ / /|  \/  | / _ \ | | | |/ ___|  *
    *   / _ \  |  \| || | | ||  \| | \ V / | |\/| || | | || | | |\___ \  *
    *  / ___ \ | |\  || |_| || |\  |  | |  | |  | || |_| || |_| | ___) | *
    * /_/   \_\|_| \_| \___/ |_| \_|  |_|  |_|  |_| \___/  \___/ |____/  *
    *                                                                    *
    *                                                                    *
    **********************************************************************

	''')

    # Get the target website from user input
    target_website = input("Enter the target website domain (e.g., example.com): ")

    # Run monitoring and detection in parallel
    monitor_thread = threading.Thread(target=monitor_requests)
    detect_thread = threading.Thread(target=detect_spike)

    monitor_thread.start()
    detect_thread.start()

    monitor_thread.join()
    detect_thread.join()
