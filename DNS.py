from scapy.all import *

def packet_callback(packet):
  if packet[TCP].payload:
    payload = str(packet[TCP].payload)
    if "GET" in payload:
      print("[+] HTTP Request from: " + packet[IP].src)
      print("[+] HTTP Request to: " + packet[IP].dst)
      if "Host" in payload:
        host = payload.split("\n")[1].split(":")[1]
        print("[+] HTTP Host: " + host)

sniff(iface="eth0", filter="tcp port 80", prn=packet_callback, store=0)
