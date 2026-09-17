#!/usr/bin/env python3
"""
Small helper to generate minimal pcap samples for recon and mqtt hijack events.

Usage:
  python3 generate_pcaps.py --out logs/recon.pcap --type recon
  python3 generate_pcaps.py --out logs/mqtt_hijack.pcap --type mqtt

"""
import argparse
try:
    from scapy.all import Ether, IP, TCP, ARP, wrpcap, Raw
except Exception:
    print("Scapy not installed. Install with: pip install scapy")
    raise

def generate_recon_pcap(path):
    packets = []
    # ARP probe
    a = Ether()/ARP(op=1, pdst='172.20.0.65', psrc='172.20.0.2')
    packets.append(a)
    # Simple HTTP GET to /wifi_scan
    p = Ether()/IP(dst='172.20.0.65')/TCP(dport=80, sport=12345, flags='PA')/Raw(load=b"GET /wifi_scan HTTP/1.1\r\nHost: 172.20.0.65\r\n\r\n")
    packets.append(p)
    wrpcap(path, packets)

def generate_mqtt_pcap(path):
    packets = []
    # MQTT packet simulation (TCP payload only) - this is a simplified view
    p = Ether()/IP(dst='172.20.0.66')/TCP(dport=1883, sport=12345, flags='PA')/Raw(load=b"MQTT-PUBLISH pv/status {\"status\":\"RUNNING\",\"session\": \"mqtt-session-123\"}\n")
    packets.append(p)
    p2 = Ether()/IP(dst='172.20.0.66')/TCP(dport=1883, sport=12345, flags='PA')/Raw(load=b"MQTT-PUBLISH pv/control {\"command\":\"HALT\"}\n")
    packets.append(p2)
    wrpcap(path, packets)


def generate_modbus_pcap(path):
    frames = []
    src = '172.20.0.70'  # attacker
    dst = '172.20.0.65'  # pv controller
    # Create Modbus TCP frames with MBAP header + PDU (function 5 write single coil)
    for i in range(1,6):
        tid = i.to_bytes(2, byteorder='big')
        pid = (0).to_bytes(2, byteorder='big')
        pdu = bytes([5]) + (1).to_bytes(2, byteorder='big') + (0xFF).to_bytes(2, byteorder='big')
        length = (len(pdu)+1).to_bytes(2, byteorder='big')
        uid = (1).to_bytes(1, byteorder='big')
        adu = tid + pid + length + uid + pdu
        ether = Ether()
        ip = IP(src=src, dst=dst)
        tcp = TCP(sport=12346 + i, dport=15002, flags='PA', seq=random.randint(0,4294967295))
        frames.append(ether/ip/tcp/Raw(load=adu))
    # Add responses from controller
    for i in range(1,6):
        tid = i.to_bytes(2, byteorder='big')
        pdu = bytes([5]) + (1).to_bytes(2, byteorder='big') + (0xFF).to_bytes(2, byteorder='big')
        adu = tid + (0).to_bytes(2, byteorder='big') + (len(pdu)+1).to_bytes(2, byteorder='big') + (1).to_bytes(1, byteorder='big') + pdu
        ether = Ether()
        ip = IP(src=dst, dst=src)
        tcp = TCP(sport=15002, dport=12346 + i, flags='PA', seq=random.randint(0,4294967295))
        frames.append(ether/ip/tcp/Raw(load=adu))
    wrpcap(path, frames)


def generate_arp_pcap(path):
    packets = []
    # ARP spoof example: attacker sends unsolicited ARP reply
    a = Ether()/ARP(op=2, pdst='172.20.0.2', psrc='172.20.0.65', hwsrc='66:55:44:33:22:11')
    packets.append(a)
    wrpcap(path, packets)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', required=True)
    parser.add_argument('--type', choices=['recon','mqtt','modbus','arp'], required=True)
    args = parser.parse_args()
    if args.type == 'recon':
        generate_recon_pcap(args.out)
    elif args.type == 'mqtt':
        generate_mqtt_pcap(args.out)
    elif args.type == 'modbus':
        generate_modbus_pcap(args.out)
    elif args.type == 'arp':
        generate_arp_pcap(args.out)
    print('Wrote', args.out)

if __name__ == '__main__':
    main()
