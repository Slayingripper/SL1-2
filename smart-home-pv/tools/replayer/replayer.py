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
POLL_INTERVAL = int(os.environ.get('REPLAYER_POLL_INTERVAL', '10'))

print('Replayer starting: pcap=', PCAP_PATH, 'server=', SERVER)

# Cache the last read pcap + mtime so we only re-read when it changed
_pcap_cache = {'mtime': None, 'pkts': None}


def load_pcap(path):
    """Read the pcap only if it changed on disk (keeps idle polling cheap)."""
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = None
    if _pcap_cache['pkts'] is None or mtime != _pcap_cache['mtime']:
        try:
            _pcap_cache['pkts'] = rdpcap(path)
            _pcap_cache['mtime'] = mtime
        except Exception as e:
            print('read pcap failed', e)
            return None
    return _pcap_cache['pkts']


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
            pkts = load_pcap(PCAP_PATH)
            if pkts is None:
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
                    pkts = load_pcap(PCAP_PATH)
                except Exception as e:
                    print('fallback generation failed', e)
                if not pkts:
                    time.sleep(POLL_INTERVAL)
                    continue
            # Replay frames once per start trigger by performing TCP/UDP send of raw payloads
            last_ts = None
            for p in pkts:
                ts = float(getattr(p, 'time', time.time()))
                if last_ts and ts > last_ts:
                    time.sleep(min(0.25, ts - last_ts))
                last_ts = ts
                if TCP in p and Raw in p:
                    dst_ip = p['IP'].dst
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
            # After playing once, notify the server (marks last_played) and stop
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
            # One-shot: pause briefly so a still-running flag doesn't cause an
            # immediate tight replay loop
            time.sleep(max(POLL_INTERVAL, 5))
        time.sleep(POLL_INTERVAL)
    except Exception as e:
        print('Replayer main loop error', e)
        time.sleep(POLL_INTERVAL)
