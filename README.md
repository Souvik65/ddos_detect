# DDOS_Detect

#Explanation of Changes:
User Input for Website Domain:

Added target_website = input("Enter the target website domain (e.g., example.com): ") to get the website domain from the user.
Use the User-Provided Domain:

The variable target_website is used in the packet_callback function to check if the packet is an HTTP request to the target website.
How to Run the Script:
Install Dependencies:

This example assumes you have a basic understanding of network traffic and have scapy installed. 
If not, you can install it using `pip install scapy`.

Ensure scapy is installed: pip install scapy
Run the Script:

Execute the script: `sudo python3 app.py`
Provide the target website domain when prompted.
