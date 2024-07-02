from scapy.all import sniff, IP, TCP, conf
import ctypes
import sys

# Callback function to process each captured packet
def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        # Check if the packet has a TCP layer
        if TCP in packet:
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            print(f"IP {ip_src} -> {ip_dst} | TCP {tcp_sport} -> {tcp_dport}")
        else:
            print(f"IP {ip_src} -> {ip_dst}")

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def main():
    try:
        # Attempt to sniff packets
        sniff(prn=packet_callback, store=0)
    except RuntimeError as e:
        # Fallback to L3socket if WinPcap/Npcap is not available
        print("Error:", e)
        print("Attempting to use L3socket...")
        conf.L3socket = conf.L3socket or conf.L3socket6
        sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    if sys.platform == 'win32':
        # Ensure script runs with admin privileges on Windows
        if not is_admin():
            print("Please run the script as an administrator.")
        else:
            main()
    else:
        main()
