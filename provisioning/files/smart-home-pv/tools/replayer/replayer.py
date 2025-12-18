#!/usr/bin/env python3
import os
import time
import json
import socket
import requests
from scapy.all import rdpcap, TCP, UDP, Raw
from scapy.all import wrpcap, Ether, IP

SERVER = os.environ.get('PV_SERVER', 'http://pv-controller')
PCAP_PATH = os.environ.get('PCAP_PATH', '/opt/pv-controller/logs/modbus.pcap')
POLL_INTERVAL = int(os.environ.get('REPLAYER_POLL_INTERVAL', '3'))

print('Replayer starting: pcap=', PCAP_PATH, 'server=', SERVER)

# Helper: send raw tcp payload to dest
def send_tcp(dst_ip, dst_port, payload):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((dst_ip, dst_port))
        if payload:
            s.sendall(payload)
        s.close()
        return True
    except Exception as e:
        print('send_tcp failed', e)
        return False

# Replayer main loop: check server replayer state
while True:
    try:
        # get control state
        r = requests.get(f"{SERVER}/replayer/state", timeout=5)
        if r.status_code == 200 and r.json().get('running'):
            print('Replayer: running - reading pcap', PCAP_PATH)
            try:
                pkts = rdpcap(PCAP_PATH)
            except Exception as e:
                print('read pcap failed', e)
                # If pcap missing, generate a minimal Modbus pcap to replay
                try:
                    print('Generating fallback Modbus PCAP...')
                    frames = []
                    s = '172.20.0.70'
                    d = '172.20.0.65'
                    for i in range(1,6):
                        # build MBAP + PDU
                        tid = i.to_bytes(2, 'big')
                        pid = (0).to_bytes(2, 'big')
                        pdu = bytes([5]) + (1).to_bytes(2, 'big') + (0xFF).to_bytes(2, 'big')
                        length = (len(pdu)+1).to_bytes(2, 'big')
                        uid = (1).to_bytes(1, 'big')
                        adu = tid + pid + length + uid + pdu
                        ether = Ether()
                        ip = IP(src=s, dst=d)
                        tcp = TCP(sport=12346+i, dport=15002, flags='PA', seq=1)
                        frames.append(ether/ip/tcp/Raw(load=adu))
                    wrpcap(PCAP_PATH, frames)
                    pkts = rdpcap(PCAP_PATH)
                except Exception as e:
                    print('fallback generation failed', e)
                    time.sleep(POLL_INTERVAL)
                    continue
                time.sleep(POLL_INTERVAL)
                continue
            # Replay frames by performing TCP/UDP send of raw payloads
            last_ts = None
            for p in pkts:
                ts = float(getattr(p, 'time', time.time()))
                if last_ts and ts > last_ts:
                    time.sleep(min(1.0, ts - last_ts))
                last_ts = ts
                if TCP in p and Raw in p:
                    dst_ip = p[ 'IP'].dst
                    dst_port = p['TCP'].dport
                    payload = bytes(p[Raw].load)
                    print('replaying TCP->', dst_ip, dst_port, 'len', len(payload))
                    send_tcp(dst_ip, dst_port, payload)
                    try:
                        with open('/opt/pv-controller/logs/replayer.log','a') as fh:
                            fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} SENT {dst_ip}:{dst_port} len={len(payload)}\n")
                    except Exception:
                        pass
                elif UDP in p and Raw in p:
                    # Not implemented in this simple replayer
                    pass
            # After playing once, log to server
            try:
                requests.post(f"{SERVER}/replayer/state", timeout=2)
            except Exception:
                pass
            try:
                with open('/opt/pv-controller/logs/replayer.log','a') as fh:
                    fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} REPLAY FINISHED\n")
            except Exception:
                pass
            print('Replay finished; waiting for next check')
        time.sleep(POLL_INTERVAL)
    except Exception as e:
        print('Replayer main loop error', e)
        time.sleep(POLL_INTERVAL)
