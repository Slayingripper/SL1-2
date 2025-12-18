#!/usr/bin/env python3
"""
Smart Home PV Controller - Cyber Range Version
This version requires REAL attacks - no shortcuts!

Key Changes from CTF Version:
1. NO /do_arp_spoof endpoint - must use actual arpspoof
2. NO direct flag endpoints - flags earned through real attacks
3. Modbus uses standard pymodbus protocol (no simplified TCP)
4. Admin panel requires authentication (credentials via phishing)
5. MQTT session tokens only visible in network traffic (packet capture required)
6. Event sequencing enforced - must complete challenges in realistic order
"""

import json
import logging
import sqlite3
import os
import socket
import secrets
import hashlib
import hmac
import threading
import time
import subprocess
import re
import shutil
from queue import Queue
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, abort, send_from_directory
from flask_cors import CORS

try:
    from pymodbus.server import StartTcpServer
    from pymodbus.datastore import ModbusSequentialDataBlock, ModbusServerContext, ModbusDeviceContext
    HAS_PYMODBUS = True
except Exception as e:
    logger.warning(f"pymodbus import failed: {e}")
    HAS_PYMODBUS = False

try:
    import paho.mqtt.client as mqtt
    HAS_PAHO = True
except Exception:
    HAS_PAHO = False

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='static', static_url_path='/static')
CORS(app)  # Enable CORS for React frontend

# ============================================================================
# FLAGS (Only distributed after REAL attacks)
# ============================================================================
FLAGS = {
    'recon': 'BSY{PV_RECON_9a7c9f3f9f}',
    'network_capture': 'BSY{PV_PCAP_ANALYSIS_8d4e21}',
    'arp_mitm': 'BSY{PV_ARP_MITM_7c3f9a}',
    'phishing': 'BSY{PV_PHISH_SUCCESS_4b8d2e}',
    'admin_access': 'BSY{PV_ADMIN_PANEL_6e9a1c}',
    'modbus_attack': 'BSY{PV_MODBUS_HALT_3f7b4d}',
    'command_injection': 'BSY{PV_CMD_INJECT_9a2e5c}'
}

# ============================================================================
# CHALLENGE STATE TRACKING
# ============================================================================
class ChallengeState:
    """Tracks student progress through realistic attack chain"""
    
    def __init__(self):
        self.events = {
            'network_scanned': False,
            'mqtt_discovered': False,
            'wifi_scanned': False,
            'arp_spoof_detected': False,  # Detected via ARP monitoring
            'packets_captured': False,     # tcpdump/wireshark required
            'mqtt_session_extracted': False,  # From pcap analysis
            'phishing_email_sent': False,
            'victim_clicked_phish': False,
            'credentials_stolen': False,
            'admin_authenticated': False,
            'modbus_traffic_analyzed': False,
            'modbus_write_executed': False,
        }
        
        self.timestamps = {}  # When each event occurred
        self.metadata = {}    # Additional context per event
        self.stolen_creds = []
        self.arp_changes = []  # MAC address changes indicating spoofing
        self.pcap_sessions = []  # MQTT sessions captured in traffic
        
        # Security event tracking for blue team
        self.security_events = []
        self.failed_logins = []
        self.anomalous_data = []
        self.blocked_ips = {}  # ip -> {blocked_at, blocked_by, reason}
        self.notifications = []  # Pop-up notifications for victim dashboard
        
        # Use RLock (reentrant lock) since add_failed_login calls add_security_event
        # while holding the lock, which would deadlock with a regular Lock
        self.lock = threading.RLock()
        # File to persist security events across page refreshes and restarts
        self.security_events_file = '/opt/pv-controller/logs/security_events.json'
        # Additional persistence files for stateful monitoring
        self.failed_logins_file = '/opt/pv-controller/logs/failed_logins.json'
        self.blocked_ips_file = '/opt/pv-controller/logs/blocked_ips.json'
        self.anomalous_data_file = '/opt/pv-controller/logs/anomalous_data.json'
        # Load persisted security events (if any)
        try:
            self._load_security_events()
        except Exception:
            # Ignore load errors - we'll create the file on first save
            pass
        # Load additional diagnostic state files (non-fatal if missing)
        try:
            self._load_failed_logins()
        except Exception:
            pass
        try:
            self._load_blocked_ips()
        except Exception:
            pass
        try:
            self._load_anomalous_data()
        except Exception:
            pass
    
    def mark_event(self, event_name, metadata=None):
        """Mark an event as completed"""
        with self.lock:
            if event_name in self.events:
                self.events[event_name] = True
                self.timestamps[event_name] = time.time()
                if metadata:
                    self.metadata[event_name] = metadata
                logger.info(f"Event completed: {event_name}")
    
    def check_event(self, event_name):
        """Check if event completed"""
        with self.lock:
            return self.events.get(event_name, False)
    
    def validate_sequence(self, required_event, dependencies):
        """Ensure challenges completed in correct order"""
        with self.lock:
            for dep in dependencies:
                if not self.events.get(dep, False):
                    return False, f"Must complete {dep} before {required_event}"
            return True, "OK"
    
    def get_flag(self, flag_type, required_events=None):
        """Get flag only if prerequisites met"""
        if required_events:
            for req in required_events:
                if not self.check_event(req):
                    return None, f"Prerequisite not met: {req}"
        
        return FLAGS.get(flag_type), "Success"
    
    def add_security_event(self, severity, category, message, details=None, source=None, ip=None):
        """Add a security event for blue team detection"""
        with self.lock:
            event = {
                'timestamp': datetime.now().isoformat(),
                'severity': severity,
                'category': category,
                'message': message,
                'details': details,
                'source': source or 'Security Monitor',
                    'ip': ip,
                'suspicious': severity in ['critical', 'high']
            }
            self.security_events.append(event)
            # Keep last 100 events
            if len(self.security_events) > 100:
                self.security_events = self.security_events[-100:]
            # Log events for visibility in container logs
            try:
                logger.warning(f"Security Event [{severity}] {category}: {message} - {details} (source: {source})")
            except Exception:
                pass
            # Persist security events to disk so they survive page refreshes
            try:
                self._save_security_events()
            except Exception:
                logger.exception("Failed to persist security events")
    
    def add_failed_login(self, username, ip_address):
        """Track failed login attempts"""
        with self.lock:
            self.failed_logins.append({
                'timestamp': datetime.now().isoformat(),
                'username': username,
                'ip_address': ip_address
            })
            # Detect brute force
            recent_failures = [f for f in self.failed_logins if f['username'] == username]
            if len(recent_failures) >= 3:
                self.add_security_event(
                    'high',
                    'Authentication',
                    f'Multiple failed login attempts detected for user: {username}',
                    f'{len(recent_failures)} failed attempts from {ip_address}',
                    'Authentication Monitor',
                    ip=ip_address
                )
                # Throttle related alerts with a timestamp to avoid flooding
                try:
                    now = datetime.now()
                    setattr(state, 'last_malformed_time', now)
                except Exception:
                    state.last_malformed_time = datetime.now()
            # Persist failed logins
            try:
                self._save_failed_logins()
            except Exception:
                logger.exception('Failed to persist failed logins')
            return

    def _save_security_events(self):
        """Persist the security events list to disk in JSON format."""
        try:
            # Ensure logs directory exists
            os.makedirs(os.path.dirname(self.security_events_file), exist_ok=True)
            with open(self.security_events_file, 'w') as fh:
                json.dump(self.security_events, fh, indent=2)
        except Exception:
            raise

    def _load_security_events(self):
        """Load persisted security events list from disk if present."""
        if not os.path.exists(self.security_events_file):
            return
        try:
            with open(self.security_events_file, 'r') as fh:
                data = json.load(fh)
            if isinstance(data, list):
                # Safely populate the list with entries (acquire lock)
                with self.lock:
                    self.security_events = data[-100:]
        except Exception:
            # Propagate to caller to handle
            raise

    def block_ip(self, ip, blocked_by='admin', reason=''):
        """Block an IP address (incident response)"""
        with self.lock:
            self.blocked_ips[ip] = {
                'blocked_at': datetime.now().isoformat(),
                'blocked_by': blocked_by,
                'reason': reason
            }
            # Persist blocked IPs
            try:
                self._save_blocked_ips()
            except Exception:
                logger.exception('Failed to persist blocked IPs')

    def is_blocked(self, ip):
        """Return whether an IP is currently blocked"""
        with self.lock:
            return ip in self.blocked_ips

    def unblock_ip(self, ip):
        """Remove an IP from the blocked list"""
        with self.lock:
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
                try:
                    self._save_blocked_ips()
                except Exception:
                    logger.exception('Failed to persist blocked IPs')

    def list_blocked_ips(self):
        """Return the dict of blocked IPs"""
        with self.lock:
            return dict(self.blocked_ips)

    # ===================== Persistent storage helpers =====================
    def _save_failed_logins(self):
        """Persist the failed_logins list to disk"""
        try:
            os.makedirs(os.path.dirname(self.failed_logins_file), exist_ok=True)
            with open(self.failed_logins_file, 'w') as fh:
                json.dump(self.failed_logins, fh, indent=2)
        except Exception:
            raise

    def _load_failed_logins(self):
        """Load persisted failed logins from disk"""
        if not os.path.exists(self.failed_logins_file):
            return
        try:
            with open(self.failed_logins_file, 'r') as fh:
                data = json.load(fh)
            if isinstance(data, list):
                with self.lock:
                    self.failed_logins = data[-500:]
        except Exception:
            raise

    def _save_blocked_ips(self):
        """Persist the blocked_ips dict to disk"""
        try:
            os.makedirs(os.path.dirname(self.blocked_ips_file), exist_ok=True)
            with open(self.blocked_ips_file, 'w') as fh:
                json.dump(self.blocked_ips, fh, indent=2)
        except Exception:
            raise

    def _load_blocked_ips(self):
        """Load persisted blocked IPs from disk"""
        if not os.path.exists(self.blocked_ips_file):
            return
        try:
            with open(self.blocked_ips_file, 'r') as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                with self.lock:
                    self.blocked_ips = data
        except Exception:
            raise

    def _save_anomalous_data(self):
        """Persist the anomalous data list to disk"""
        try:
            os.makedirs(os.path.dirname(self.anomalous_data_file), exist_ok=True)
            with open(self.anomalous_data_file, 'w') as fh:
                json.dump(self.anomalous_data, fh, indent=2)
        except Exception:
            raise

    def _load_anomalous_data(self):
        """Load persisted anomalous data from disk"""
        if not os.path.exists(self.anomalous_data_file):
            return
        try:
            with open(self.anomalous_data_file, 'r') as fh:
                data = json.load(fh)
            if isinstance(data, list):
                with self.lock:
                    self.anomalous_data = data[-500:]
        except Exception:
            raise

    def add_anomalous_data(self, anomaly):
        """Add an anomalous data point and persist it"""
        with self.lock:
            self.anomalous_data.append(anomaly)
            # Keep memory limited
            if len(self.anomalous_data) > 500:
                self.anomalous_data = self.anomalous_data[-500:]
            try:
                self._save_anomalous_data()
            except Exception:
                logger.exception('Failed to persist anomalous data')

state = ChallengeState()

# ============================================================================
# SYSTEM CONFIGURATION
# ============================================================================
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"  # Simpler password for brute force demo
WIFI_PASSWORD = "super-secret-123"     # Discovered via /wifi_scan, but NOT admin password

pv_status = {
    "status": "RUNNING",
    "power_kw": 3.2,
    "voltage_v": 240,
    "current_a": 13.3,
    "last_update": time.time()
}

# JWT-like tokens with expiration
active_tokens = {}  # token -> {username, expires, type}

# MQTT session token (changes periodically, visible only in network traffic)
MQTT_SESSION_TOKEN = f"mqtt-session-{secrets.token_hex(8)}"

def generate_token(username, token_type='api', expires_in=1800, ip_address=None):
    """Generate token with expiration (30 min default)"""
    token = secrets.token_urlsafe(32)
    active_tokens[token] = {
        'username': username,
        'type': token_type,
        'expires': time.time() + expires_in,
        'created': time.time()
    }
    # Store the originating IP (if provided) for token revocation / block enforcement
    if ip_address:
        active_tokens[token]['ip'] = ip_address
    return token

def validate_token(token, required_type=None):
    """Validate token and check expiration"""
    token_data = active_tokens.get(token)
    if not token_data:
        return None
    
    if token_data['expires'] < time.time():
        del active_tokens[token]
        return None
    
    if required_type and token_data['type'] != required_type:
        return None
    # Check if token's originating IP is blocked
    token_ip = token_data.get('ip')
    if token_ip and state.is_blocked(token_ip):
        logger.warning(f"Token invalidated - originating IP is blocked: {token_ip}")
        return None
    # Also block requests from request.remote_addr if that IP is blocked (protect UI/API endpoints)
    try:
        if request and state.is_blocked(request.remote_addr):
            logger.warning(f"Request blocked - IP is blocked: {request.remote_addr}")
            return None
    except Exception:
        pass
    
    return token_data


def revoke_tokens_for_ip(ip_address):
    """Revoke any active tokens originating from ip_address"""
    revoked = 0
    tokens_to_revoke = []
    for t, data in list(active_tokens.items()):
        if data.get('ip') == ip_address:
            tokens_to_revoke.append(t)
    for t in tokens_to_revoke:
        del active_tokens[t]
        revoked += 1
    if revoked:
        logger.warning(f"Revoked {revoked} tokens for IP: {ip_address}")
    return revoked


# Automatic blocked-IP maintenance: expire blocks after some time (default 5 minutes)
BLOCK_TTL_SECONDS = int(os.getenv('BLOCK_TTL_SECONDS', '300'))

def blocked_ips_maintenance_thread():
    """Background thread to automatically unblock IPs after TTL"""
    while True:
        with state.lock:
            to_unblock = []
            for ip, meta in list(state.blocked_ips.items()):
                blocked_at = meta.get('blocked_at')
                try:
                    # Parse isoformat string
                    blocked_dt = datetime.fromisoformat(blocked_at)
                    if (datetime.now() - blocked_dt).total_seconds() > BLOCK_TTL_SECONDS:
                        to_unblock.append(ip)
                except Exception:
                    # If parse fails, optionally check 'blocked_at_ts'
                    try:
                        if float(meta.get('blocked_at_ts', 0)) + BLOCK_TTL_SECONDS < time.time():
                            to_unblock.append(ip)
                    except Exception:
                        pass
            for ip in to_unblock:
                try:
                    logger.info(f"Auto-unblocking IP: {ip} after TTL {BLOCK_TTL_SECONDS}s")
                    state.unblock_ip(ip)
                except Exception:
                    logger.exception(f"Failed to auto-unblock IP: {ip}")
        time.sleep(10)

# ============================================================================
# ARP SPOOFING DETECTION
# ============================================================================
def arp_monitor_thread():
    """
    Monitor ARP table for changes indicating MITM attack
    This runs continuously and detects when attacker uses arpspoof
    """
    baseline_arp = {}
    
    while True:
        try:
            # Parse ARP table: prefer `arp -an`, else try `ip neigh`, else /proc/net/arp
            result = ''
            try:
                if shutil.which('arp'):
                    result = subprocess.check_output(['arp', '-an'], timeout=5).decode()
                elif shutil.which('ip'):
                    result = subprocess.check_output(['ip', 'neigh'], timeout=5).decode()
                else:
                    with open('/proc/net/arp', 'r') as f:
                        result = f.read()
            except Exception as e:
                logger.debug(f"Error reading ARP: {e}")
            current_arp = {}
            
            for line in result.splitlines():
                # Try parse: arp -an output '(172.20.0.72) at 02:42:ac:14:00:48 [ether] on eth0'
                match = re.search(r'\(([\d\.]+)\) at ([0-9a-f:]+)', line, re.IGNORECASE)
                if match:
                    ip, mac = match.groups()
                    current_arp[ip] = mac.lower()
                    continue
                # Try parse: ip neigh output '172.20.0.72 dev eth0 lladdr 02:42:ac:14:00:48 REACHABLE'
                match = re.search(r'([\d\.]+).*lladdr\s+([0-9a-f:]+)', line, re.IGNORECASE)
                if match:
                    ip, mac = match.groups()
                    current_arp[ip] = mac.lower()
                    continue
                # Try parse: /proc/net/arp format '172.20.0.72 0x1 02:42:ac:14:00:48 * eth0'
                match = re.search(r'([\d\.]+)\s+0x[0-9a-f]+\s+([0-9a-f:]+)\s+', line, re.IGNORECASE)
                if match:
                    ip, mac = match.groups()
                    current_arp[ip] = mac.lower()
            
            # Detect MAC address changes (ARP spoofing indicator)
            for ip, mac in current_arp.items():
                if ip in baseline_arp and baseline_arp[ip] != mac:
                    logger.warning(f"⚠️  ARP SPOOFING DETECTED: {ip} changed from {baseline_arp[ip]} to {mac}")
                    state.mark_event('arp_spoof_detected', {
                        'ip': ip,
                        'old_mac': baseline_arp[ip],
                        'new_mac': mac,
                        'detected_at': datetime.now().isoformat()
                    })
                    state.arp_changes.append({
                        'ip': ip,
                        'old_mac': baseline_arp[ip],
                        'new_mac': mac,
                        'timestamp': time.time()
                    })
                    # Report security event for ARP spoofing with affected IP
                    state.add_security_event(
                        'critical',
                        'ARP Spoofing',
                        'ARP spoofing detected for device',
                        f'IP {ip} has changed MAC from {baseline_arp[ip]} to {mac}',
                        'ARP Monitor',
                        ip=ip
                    )
            
            baseline_arp = current_arp
            time.sleep(10)  # Check every 10 seconds
            
        except subprocess.TimeoutExpired:
            logger.error("ARP command timed out")
            time.sleep(15)
        except Exception as e:
            logger.error(f"ARP monitor error: {e}")
            time.sleep(15)

# Start ARP monitoring in background
threading.Thread(target=arp_monitor_thread, daemon=True).start()
# Start blocked IP maintenance thread
threading.Thread(target=blocked_ips_maintenance_thread, daemon=True).start()

# ============================================================================
# MQTT INTEGRATION (Session tokens only in network traffic)
# ============================================================================
MQTT_BROKER = os.getenv('MQTT_HOST', 'mosquitto')
mqtt_client = None

def on_mqtt_connect(client, userdata, flags, rc):
    if rc == 0:
        logger.info("✓ Connected to MQTT broker")
        client.subscribe('pv/control')
        client.subscribe('pv/telemetry')
        client.subscribe('pv/admin/#')
        
        # Publish status with session token (visible in network capture)
        publish_mqtt_status()
    else:
        logger.error(f"MQTT connection failed: {rc}")

def on_mqtt_message(client, userdata, msg):
    """Handle MQTT messages (control commands)"""
    try:
        payload = json.loads(msg.payload.decode())
        
        # Detect anomalous telemetry data (attacks)
        if msg.topic == 'pv/telemetry':
            # Accept both `power_kw` and the alternate `power` field (telemetry seeder)
            power = payload.get('power_kw') if 'power_kw' in payload else payload.get('power')
            voltage = payload.get('voltage_v')
            current = payload.get('current_a')
            
            # Only analyze if this is a proper PV telemetry message (has power_kw or power field)
            # Background noise messages use `ts`/`value` format and will be ignored
            if 'power_kw' not in payload and 'power' not in payload:
                logger.debug(f"Ignored non-PV telemetry message: {json.dumps(payload)[:60]}")
                return  # Ignore background noise telemetry
            
            # Detect malformed data (type confusion attacks)
            # Detect malformed data (type confusion attacks)
            if power is not None and not isinstance(power, (int, float)):
                # Throttle malformed events to avoid flooding: at most one per 60 seconds
                last_malformed = state.get('last_malformed_time') if hasattr(state, 'get') else None
                now = datetime.now()
                try:
                    last = getattr(state, 'last_malformed_time', None)
                except Exception:
                    last = None
                if last is None or (now - last).total_seconds() > 60:
                    # build small payload snippet for details (only power info)
                    snippet = json.dumps({'power_kw': power}) if 'power_kw' in payload else json.dumps({'power': power})
                    state.add_security_event(
                        'critical',
                        'Data Integrity',
                        'Malformed telemetry data detected',
                        f'Invalid power reading received: {snippet}. Possible type confusion attack or protocol violation.',
                        'MQTT Monitor'
                    )

                    
                    try:
                        setattr(state, 'last_malformed_time', now)
                    except Exception:
                        state.last_malformed_time = now
                    # Persist the anomaly to anomalous data
                    try:
                        state.add_anomalous_data({
                            'timestamp': datetime.now().isoformat(),
                            'reason': 'malformed_type',
                            'payload': payload
                        })
                    except Exception:
                        logger.exception('Failed to append anomalous data')
                return
            
            # Detect impossible power readings
            if power and power > 100:
                state.add_security_event(
                    'critical',
                    'Data Integrity',
                    'Impossible power reading detected in MQTT telemetry',
                    f'Power: {power} kW exceeds physical limits (residential PV max ~10kW). Possible data injection attack.',
                    'MQTT Monitor'
                )
                try:
                    state.add_anomalous_data({
                        'timestamp': datetime.now().isoformat(),
                        'reason': 'impossible_power',
                        'power': power,
                        'payload': payload
                    })
                except Exception:
                    logger.exception('Failed to append anomalous data')
            
            # Detect negative power (unusual)
            if power and power < -10:
                state.add_security_event(
                    'high',
                    'Anomaly Detection',
                    'Unusual negative power reading detected',
                    f'Power: {power} kW indicates potential grid attack or sensor manipulation.',
                    'MQTT Monitor'
                )
                try:
                    state.add_anomalous_data({
                        'timestamp': datetime.now().isoformat(),
                        'reason': 'negative_power',
                        'power': power,
                        'payload': payload
                    })
                except Exception:
                    logger.exception('Failed to append anomalous data')
            
            # Detect all zeros (system offline or DoS)
            if power == 0 and voltage == 0 and current == 0:
                state.add_security_event(
                    'high',
                    'System Health',
                    'All telemetry sensors reading zero',
                    'This may indicate system shutdown, sensor failure, or DoS attack.',
                    'MQTT Monitor'
                )
                try:
                    state.add_anomalous_data({
                        'timestamp': datetime.now().isoformat(),
                        'reason': 'all_zero',
                        'payload': payload
                    })
                except Exception:
                    logger.exception('Failed to append anomalous data')
        
        if msg.topic == 'pv/control':
            command = payload.get('command', '').upper()
            session = payload.get('session', '')
            
            # Validate session token (must be stolen from network traffic)
            if session != MQTT_SESSION_TOKEN:
                logger.warning(f"Invalid MQTT session token: {session}")
                state.add_security_event(
                    'high',
                    'Authentication',
                    'Invalid MQTT session token attempt',
                    f'Attempted command: {command} with invalid session token',
                    'MQTT Monitor'
                )
                return
            
            logger.info(f"Valid MQTT command received: {command}")
            state.mark_event('mqtt_session_extracted', {'session': session})
            
            if command == 'HALT':
                pv_status['status'] = 'HALTED'
                pv_status['power_kw'] = 0
                logger.warning("🛑 PV SYSTEM HALTED VIA MQTT")
                state.add_security_event(
                    'critical',
                    'System Control',
                    'System HALT command executed via MQTT',
                    'PV system forcibly halted through MQTT control channel. Possible remote attack.',
                    'MQTT Monitor'
                )
                
    except Exception as e:
        logger.error(f"MQTT message error: {e}")

def publish_mqtt_status():
    """Publish system status to MQTT (includes session token in metadata)"""
    if mqtt_client and mqtt_client.is_connected():
        status_msg = {
            'status': pv_status['status'],
            'power_kw': pv_status['power_kw'],
            'timestamp': time.time(),
            'session': MQTT_SESSION_TOKEN  # Only visible in packet capture!
        }
        mqtt_client.publish('pv/status', json.dumps(status_msg), qos=1)

def mqtt_telemetry_thread():
    """Publish telemetry data periodically"""
    while True:
        try:
            if mqtt_client and mqtt_client.is_connected():
                telemetry = {
                    'power_kw': pv_status['power_kw'] + (hash(time.time()) % 100) / 100,
                    'voltage_v': pv_status['voltage_v'] + (hash(time.time()) % 10),
                    'current_a': pv_status['current_a'] + (hash(time.time()) % 5) / 10,
                    'timestamp': time.time()
                }
                mqtt_client.publish('pv/telemetry', json.dumps(telemetry), qos=0)
                
                # Occasionally publish status (with session token)
                if int(time.time()) % 30 == 0:
                    publish_mqtt_status()
            
            time.sleep(2)
        except Exception as e:
            logger.error(f"Telemetry error: {e}")
            time.sleep(5)

if HAS_PAHO:
    try:
        mqtt_client = mqtt.Client()
        mqtt_client.on_connect = on_mqtt_connect
        mqtt_client.on_message = on_mqtt_message
        mqtt_client.connect(MQTT_BROKER, 1883, 60)
        mqtt_client.loop_start()
        
        # Start telemetry publisher
        threading.Thread(target=mqtt_telemetry_thread, daemon=True).start()
        logger.info("✓ MQTT client started")
    except Exception as e:
        logger.error(f"MQTT client failed: {e}")
else:
    logger.warning("⚠️  paho-mqtt not available")

# ============================================================================
# MODBUS SERVER (Real protocol, not simplified TCP)
# ============================================================================

# Global Modbus context for monitoring
modbus_context = None
last_modbus_alert_time = None

def modbus_monitor_thread():
    """Monitor Modbus coils for changes"""
    global modbus_context, last_modbus_alert_time
    last_coil1_value = False
    
    while True:
        try:
            if modbus_context is not None:
                # Read coil 1 value
                values = modbus_context[0].getValues(1, 1, 1)  # fc=1 (coils), address=1, count=1
                coil1_value = bool(values[0]) if values else False
                
                # Detect change from False to True
                if coil1_value and not last_coil1_value:
                    logger.critical("🛑 PV SYSTEM HALTED VIA MODBUS (Coil 1 set to TRUE)")
                    pv_status['status'] = 'HALTED'
                    pv_status['power_kw'] = 0
                    
                    # Only alert if this is a new attack (within last 5 seconds)
                    # Prevents duplicate alerts on container restart
                    now = datetime.now()
                    if last_modbus_alert_time is None or (now - last_modbus_alert_time).total_seconds() > 5:
                        state.add_security_event(
                            'critical',
                            'ICS Protocol',
                            'Unauthorized Modbus write operation detected',
                            'Coil 1 was set to TRUE, triggering system HALT. This indicates direct ICS protocol exploitation.',
                            'Modbus Monitor'
                        )
                        last_modbus_alert_time = now
                    
                    # Write flag to log file
                    try:
                        with open('/opt/pv-controller/logs/modbus_attacks.log', 'a') as f:
                            f.write(f"{datetime.now().isoformat()},MODBUS_HALT,{FLAGS['modbus_attack']},coil_1\n")
                    except Exception as e:
                        logger.error(f"Failed to write modbus log: {e}")
                
                last_coil1_value = coil1_value
        except Exception as e:
            logger.error(f"Modbus monitor error: {e}")
        
        time.sleep(1)

def modbus_write_callback(slave_id, function_code, address, values):
    """Called when Modbus WRITE operation occurs"""
    logger.warning(f"🔴 MODBUS WRITE DETECTED: slave={slave_id}, fc={function_code}, addr={address}, values={values}")
    
    # Don't create security event here - let the monitoring thread detect the coil change
    # This prevents duplicate alerts
    
    state.mark_event('modbus_write_executed', {
        'address': address,
        'values': values,
        'function_code': function_code
    })
    
    # Coil 1 = HALT control
    if address == 1 and values and values[0]:
        logger.critical("🛑 PV SYSTEM HALTED VIA MODBUS")
        pv_status['status'] = 'HALTED'
        pv_status['power_kw'] = 0
        
        # Write flag to log file (student must check logs)
        try:
            with open('/opt/pv-controller/logs/modbus_attacks.log', 'a') as f:
                f.write(f"{datetime.now().isoformat()},MODBUS_HALT,{FLAGS['modbus_attack']},coil_{address}\n")
        except Exception as e:
            logger.error(f"Failed to write modbus log: {e}")

def modbus_server_thread():
    """Run Modbus TCP server"""
    global modbus_context
    
    if not HAS_PYMODBUS:
        logger.warning("⚠️  pymodbus not available - Modbus server disabled")
        return
    
    try:
        # Define Modbus registers (pymodbus 3.x API)
        device = ModbusDeviceContext(
            di=ModbusSequentialDataBlock(0, [0]*100),  # Discrete Inputs
            co=ModbusSequentialDataBlock(0, [0]*100),  # Coils
            hr=ModbusSequentialDataBlock(0, [0]*100),  # Holding Registers
            ir=ModbusSequentialDataBlock(0, [0]*100),  # Input Registers
        )
        
        context = ModbusServerContext(devices=device, single=True)
        modbus_context = context  # Store globally for monitoring
        
        MODBUS_PORT = int(os.getenv('MODBUS_PORT', '15002'))
        logger.info(f"🔧 Starting Modbus TCP server on port {MODBUS_PORT}...")
        
        # Start monitoring thread
        threading.Thread(target=modbus_monitor_thread, daemon=True).start()
        
        # Start server (blocking call)
        StartTcpServer(
            context=context,
            address=("0.0.0.0", MODBUS_PORT),
        )
    except Exception as e:
        logger.error(f"Modbus server error: {e}")

# Start Modbus server in background
threading.Thread(target=modbus_server_thread, daemon=True).start()

# ============================================================================
# HTTP ROUTES - Reconnaissance
# ============================================================================

@app.route("/")
def index():
    return jsonify({
        "service": "Smart Home PV Controller",
        "version": "2.1.4",
        "status": pv_status["status"],
        "manufacturer": "SolarTech Industries",
        "model": "PV-INV-3200"
    })

@app.route("/wifi_scan")
def wifi_scan():
    """
    WiFi credential discovery (breadcrumb for students)
    This is intentionally easy to find, but WiFi password != admin password!
    """
    state.mark_event('wifi_scanned')
    
    return jsonify({
        "ssid": "HomeWiFi_PV",
        "password": WIFI_PASSWORD,
        "security": "WPA2-PSK",
        "note": "Weak password - dictionary attack susceptible",
        "flag": FLAGS['recon']
    })

# ============================================================================
# HTTP ROUTES - Phishing Infrastructure
# ============================================================================

# Victim email inbox (simulated)
victim_inbox = []

@app.route("/api/send_phishing_email", methods=["POST"])
def send_phishing_email():
    """
    Attacker sends phishing email to victim
    Victim container periodically checks this endpoint
    """
    data = request.json or {}
    
    email = {
        'to': data.get('to', 'admin@pv-controller.local'),
        'subject': data.get('subject', ''),
        'body': data.get('body', ''),
        'link': data.get('link', ''),
        'sent_at': time.time(),
        'id': secrets.token_hex(8)
    }
    
    victim_inbox.append(email)
    state.mark_event('phishing_email_sent', email)
    # Security event for delivered phishing email (notify Blue Team)
    state.add_security_event('high', 'Phishing', 'Phishing email sent to victim', f"Subject: {email['subject']}", 'Phishing Infrastructure', ip=request.remote_addr)
    
    logger.info(f"📧 Phishing email queued: {email['subject']}")
    
    return jsonify({"result": "ok", "email_id": email['id']})

@app.route("/api/internal/inbox", methods=["GET"])
def victim_inbox_check():
    """Victim checks for new emails (internal endpoint)"""
    return jsonify(victim_inbox)

@app.route("/api/internal/phish_clicked", methods=["POST"])
def phish_clicked():
    """Victim clicked phishing link"""
    data = request.json or {}
    email_id = data.get('email_id')
    
    state.mark_event('victim_clicked_phish', {'email_id': email_id})
    state.add_security_event('medium', 'Phishing', 'Victim clicked phishing link', f'Email ID: {email_id}', 'Phishing Infrastructure', ip=request.remote_addr)
    logger.warning(f"⚠️  Victim clicked phishing link: {email_id} from {request.remote_addr}")
    
    return jsonify({"result": "ok"})

@app.route("/api/internal/phish_submitted", methods=["POST"])
def phish_submitted():
    """Victim submitted credentials to phishing page"""
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    email_id = data.get('email_id')
    
    if username and password:
        state.stolen_creds.append({
            'username': username,
            'password': password,
            'timestamp': time.time()
        })
        
        state.mark_event('credentials_stolen', {'username': username})
        state.add_security_event('critical', 'Phishing', 'Credentials submitted to phishing page', f'User: {username}', 'Phishing Infrastructure', ip=request.remote_addr)
        logger.critical(f"🚨 CREDENTIALS STOLEN VIA PHISHING: {username} from {request.remote_addr}")
        
        # Clear the inbox to prevent re-processing
        if email_id:
            global victim_inbox
            victim_inbox = [e for e in victim_inbox if e.get('id') != email_id]
        
        # Write to log
        try:
            with open('/opt/pv-controller/logs/phishing.log', 'a') as f:
                f.write(f"{datetime.now().isoformat()},{username},{password}\n")
        except:
            pass
        
        return jsonify({"result": "ok", "flag": FLAGS['phishing']})
    
    return jsonify({"error": "Invalid credentials"}), 400

@app.route("/api/internal/stolen_creds", methods=["GET"])
def get_stolen_creds():
    """
    Check if any credentials have been stolen via phishing
    Used by attacker script to detect successful phishing
    
    Query params:
    - after: Unix timestamp - only return credentials stolen after this time
    """
    after_ts = request.args.get('after', type=float, default=0)
    
    # Filter credentials by timestamp if specified
    if after_ts > 0:
        recent_creds = [c for c in state.stolen_creds if c.get('timestamp', 0) > after_ts]
        if recent_creds:
            latest = recent_creds[-1]
            return jsonify({
                "stolen": True,
                "username": latest.get('username'),
                "password": latest.get('password'),
                "timestamp": latest.get('timestamp'),
                "count": len(recent_creds)
            })
        return jsonify({"stolen": False, "count": 0})
    
    # Return all if no timestamp filter
    if state.stolen_creds:
        latest = state.stolen_creds[-1]
        return jsonify({
            "stolen": True,
            "username": latest.get('username'),
            "password": latest.get('password'),
            "timestamp": latest.get('timestamp'),
            "count": len(state.stolen_creds)
        })
    return jsonify({"stolen": False, "count": 0})

@app.route("/api/internal/clear_stolen_creds", methods=["POST"])
def clear_stolen_creds():
    """Clear stolen credentials - used at start of new phishing attack"""
    state.stolen_creds.clear()
    return jsonify({"result": "ok", "cleared": True})

# ============================================================================
# HTTP ROUTES - Admin Authentication
# ============================================================================

@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    """
    Admin login - requires REAL credentials obtained via phishing
    NO SQL injection - realistic authentication
    """
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    client_ip = request.remote_addr
    
    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400
    
    # Check if area is blocked for this IP
    if state.is_blocked(client_ip):
        logger.warning(f"Blocked IP {client_ip} attempted login")
        state.add_security_event('medium', 'Authentication', 'Blocked IP attempted admin login', f'IP: {client_ip}', 'Authentication Service', ip=client_ip)
        return jsonify({"error": "Access denied"}), 403

    # Check credentials
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        token = generate_token(username, 'admin', expires_in=1800, ip_address=client_ip)
        
        state.mark_event('admin_authenticated', {'username': username})
        state.add_security_event(
            'medium',
            'Authentication',
            f'Admin login successful from {client_ip}',
            f'User {username} authenticated successfully',
            'Authentication Service',
            ip=client_ip
        )
        logger.info(f"✓ Admin authenticated: {username}")
        
        return jsonify({
            "token": token,
            "username": username,
            "expires_in": 1800
        })
    
    # Track failed login
    state.add_failed_login(username, client_ip)
    logger.warning(f"Failed admin login attempt: {username} from {client_ip}")
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/assets/<path:filename>")
def serve_assets(filename):
    """Serve React build assets (JS, CSS)"""
    admin_dist_dir = os.path.join(os.path.dirname(__file__), 'admin-dashboard', 'dist', 'assets')
    return send_from_directory(admin_dist_dir, filename)

@app.route("/admin")
@app.route("/admin/<path:path>")
def serve_admin_ui(path=''):
    """Serve React admin dashboard"""
    admin_dist_dir = os.path.join(os.path.dirname(__file__), 'admin-dashboard', 'dist')
    
    # Don't serve assets here (handled by /assets route above)
    if path and not path.startswith('assets'):
        file_path = os.path.join(admin_dist_dir, path)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            return send_from_directory(admin_dist_dir, path)
    
    # Always serve index.html for /admin and /admin/* routes (React routing)
    index_path = os.path.join(admin_dist_dir, 'index.html')
    if os.path.exists(index_path):
        return send_from_directory(admin_dist_dir, 'index.html')
    
    # Fallback if React app not built yet
    return """
    <html><body style="background:#0a192f;color:#64ffda;font-family:monospace;padding:50px;">
    <h1>⚠️ Admin Dashboard Not Built</h1>
    <p>To enable the React admin dashboard:</p>
    <pre>
    cd admin-dashboard
    npm install
    npm run build
    </pre>
    <p>Then restart the server.</p>
    <p style="margin-top:30px;color:#8892b0;">
    Alternatively, use the development server:<br>
    cd admin-dashboard && npm run dev
    </p>
    </body></html>
    """, 503

@app.route("/api/admin/flag")
def get_admin_flag():
    """Return flag after successful admin authentication"""
    auth_header = request.headers.get('Authorization', '')
    
    if not auth_header.startswith('Bearer '):
        return jsonify({"error": "Missing authentication token"}), 401
    
    token = auth_header.split(' ', 1)[1]
    
    # Simple token validation (in production use JWT)
    if not state.check_event('admin_authenticated'):
        return jsonify({"error": "Admin not authenticated"}), 403
    
    return jsonify({
        "flag": FLAGS['admin_access'],
        "message": "Congratulations! You've gained admin access.",
        "earned_at": datetime.now().isoformat()
    })

@app.route("/api/admin/logs")
def get_admin_logs_api():
    """Return system logs for admin dashboard"""
    auth_header = request.headers.get('Authorization', '')
    
    if not auth_header.startswith('Bearer '):
        return jsonify({"error": "Missing authentication token"}), 401
    
    logs = [
        "System startup completed",
        "MQTT broker connection established",
        "Modbus TCP server started on port 502",
        "ARP monitoring thread started",
        "Admin authentication successful"
    ]
    
    return jsonify({"logs": logs})

# ============================================================================
# HTTP ROUTES - Flags
# ============================================================================

@app.route("/flag/<flag_type>")
def get_flag(flag_type):
    """
    Distribute flags only after prerequisites met
    No shortcuts - must complete real attacks!
    """
    
    # Define prerequisites for each flag
    prerequisites = {
        'recon': [],  # Free flag
        'network_capture': ['arp_spoof_detected'],
        'arp_mitm': ['arp_spoof_detected', 'packets_captured'],
        'phishing': ['credentials_stolen'],
        'admin_access': ['admin_authenticated'],
        'modbus_attack': ['modbus_write_executed'],
    }
    
    required = prerequisites.get(flag_type, [])
    
    for req in required:
        if not state.check_event(req):
            return jsonify({
                "error": "Prerequisites not met",
                "required": req,
                "hint": f"You must complete {req} first"
            }), 403
    
    flag = FLAGS.get(flag_type)
    if flag:
        return jsonify({"flag": flag, "earned_at": datetime.now().isoformat()})
    
    return jsonify({"error": "Invalid flag type"}), 404

# ============================================================================
# HTTP ROUTES - Status & Logs
# ============================================================================

@app.route("/api/status")
def api_status():
    """Public status endpoint"""
    return jsonify({
        "status": pv_status['status'],
        "power_kw": pv_status['power_kw'],
        "voltage_v": pv_status['voltage_v'],
        "current_a": pv_status['current_a'],
        "uptime": int(time.time() - state.timestamps.get('network_scanned', time.time())),
        "mqtt_connected": mqtt_client.is_connected() if mqtt_client else False
    })

@app.route("/api/admin/logs/<log_type>")
def get_admin_logs(log_type):
    """Admin logs (requires authentication)"""
    auth_header = request.headers.get('Authorization', '')
    
    if not auth_header.startswith('Bearer '):
        return jsonify({"error": "No authorization"}), 401
    
    token = auth_header.split(' ', 1)[1]
    token_data = validate_token(token, 'admin')
    
    if not token_data:
        return jsonify({"error": "Invalid or expired token"}), 403
    
    # Read log file
    log_file = f"/opt/pv-controller/logs/{log_type}.log"
    
    if not os.path.exists(log_file):
        return jsonify({"error": "Log file not found"}), 404
    
    try:
        with open(log_file, 'r') as f:
            lines = f.readlines()[-100:]  # Last 100 lines
        
        return jsonify({"logs": [l.strip() for l in lines]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/challenge/status")
def challenge_status():
    """Show challenge progress (for students)"""
    return jsonify({
        "events_completed": {k: v for k, v in state.events.items() if v},
        "arp_changes_detected": len(state.arp_changes),
        "credentials_stolen": len(state.stolen_creds),
        "flags_available": [k for k, v in state.events.items() if v and k in FLAGS]
    })

@app.route("/api/admin/security/events")
def get_security_events():
    """Get security events for blue team monitoring"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    token_data = validate_token(token)
    
    if not token_data:
        return jsonify({"error": "Invalid or expired token"}), 403
    
    # Return security events
    return jsonify({
        "events": state.security_events[-50:],  # Last 50 events
        "failed_logins_count": len(state.failed_logins),
        "anomalous_data_count": len(state.anomalous_data)
    })


@app.route("/api/admin/security/failed_logins")
def get_failed_logins():
    """Return failed login attempts (admin only)"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    token_data = validate_token(token)
    if not token_data:
        return jsonify({"error": "Invalid or expired token"}), 403

    with state.lock:
        return jsonify({"failed_logins": list(state.failed_logins)})


@app.route("/api/admin/security/anomalies")
def get_anomalous_data():
    """Return anomalous telemetry data (admin only)"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    token_data = validate_token(token)
    if not token_data:
        return jsonify({"error": "Invalid or expired token"}), 403

    with state.lock:
        return jsonify({"anomalies": list(state.anomalous_data)})

@app.route("/api/admin/security/events/export")
def export_security_events():
    """Export security events as CSV for incident response"""
    import csv
    from io import StringIO
    
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    token_data = validate_token(token)
    
    if not token_data:
        return jsonify({"error": "Invalid or expired token"}), 403
    
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Timestamp', 'Severity', 'Category', 'Title', 'Details', 'Source', 'IP'])
    
    for event in state.security_events:
        writer.writerow([
            event['timestamp'],
            event['severity'],
            event['category'],
            event.get('message') or event.get('title'),
            event['details'],
            event['source']
            , event.get('ip')
        ])
    
    output.seek(0)
    return output.getvalue(), 200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': f'attachment; filename=security_events_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    }


@app.route("/api/admin/security/failed_logins/export")
def export_failed_logins():
    """Export failed login attempts as CSV for incident response"""
    import csv
    from io import StringIO

    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    token_data = validate_token(token)
    if not token_data:
        return jsonify({"error": "Invalid or expired token"}), 403

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Timestamp', 'Username', 'IP Address'])

    for f in state.failed_logins:
        writer.writerow([f.get('timestamp'), f.get('username'), f.get('ip_address')])

    output.seek(0)
    return output.getvalue(), 200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': f'attachment; filename=failed_logins_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    }


@app.route("/api/admin/security/blocked/export")
def export_blocked_ips():
    """Export blocked IPs as CSV"""
    import csv
    from io import StringIO

    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    token_data = validate_token(token)
    if not token_data:
        return jsonify({"error": "Invalid or expired token"}), 403

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['IP', 'Blocked At', 'Blocked By', 'Reason'])

    for ip, meta in state.blocked_ips.items():
        writer.writerow([ip, meta.get('blocked_at'), meta.get('blocked_by'), meta.get('reason')])

    output.seek(0)
    return output.getvalue(), 200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': f'attachment; filename=blocked_ips_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    }


@app.route("/api/admin/security/anomalies/export")
def export_anomalous_data():
    """Export anomalous telemetry data as JSON"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    token_data = validate_token(token)
    if not token_data:
        return jsonify({"error": "Invalid or expired token"}), 403

    # Return JSON dump of anomalous data
    content = json.dumps(state.anomalous_data, indent=2)
    return content, 200, {
        'Content-Type': 'application/json',
        'Content-Disposition': f'attachment; filename=anomalies_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    }

@app.route("/api/attacker/phishing", methods=["POST"])
def trigger_phishing_notification():
    """Trigger phishing notification for blue team (simulates realistic email/alert)"""
    data = request.get_json() or {}
    phishing_url = data.get('url', 'http://172.20.0.70:8000/login.html')
    message = data.get('message', 'Urgent: System Security Update Required')
    
    # Create a high-severity security event that will appear as a notification
    state.add_security_event(
        severity='medium',
        category='Suspicious Email',
        message=message,
        details=f'A suspicious email was received requesting immediate action. Link: {phishing_url}',
        source='Email Gateway',
        ip=request.remote_addr
    )
    
    # Add pop-up notification for victim dashboard
    with state.lock:
        notification = {
            'id': len(state.notifications) + 1,
            'timestamp': datetime.now().isoformat(),
            'type': 'urgent',
            'title': '⚠️ System Alert',
            'message': message,
            'link': phishing_url,
            'link_text': 'Verify Credentials',
            'read': False
        }
        state.notifications.append(notification)
        # Keep last 20 notifications
        if len(state.notifications) > 20:
            state.notifications = state.notifications[-20:]
    
    logger.info(f"🎣 Phishing notification triggered by {request.remote_addr}: {message}")
    
    return jsonify({
        'success': True,
        'message': 'Phishing bait deployed successfully'
    })

@app.route("/api/notifications")
def get_notifications():
    """Get notifications for victim dashboard (no auth required - visible to all)"""
    with state.lock:
        return jsonify({
            'notifications': state.notifications,
            'unread_count': sum(1 for n in state.notifications if not n.get('read', False))
        })


@app.route("/api/containers")
def get_container_info():
    """Return a small mapping of container connection info for UI commands
    This is intentionally static mapping matching docker-compose settings.
    """
    return jsonify({
        'hackerlab': {
            'name': 'scl-hackerlab',
            'internal_ip': '172.20.0.2',
            'ssh_user': 'root',
            'host_ssh_port': 2222
        },
        'attacker': {
            'name': 'scl-challenge-smart-home-pv-attacker',
            'internal_ip': '172.20.0.70',
            'ssh_user': 'attacker',
            'host_ssh_port': 2224
        },
        'pv_controller': {
            'name': 'scl-challenge-smart-home-pv',
            'internal_ip': '172.20.0.65',
            'admin_host_port': 8081
        }
    })

@app.route("/api/notifications/<int:notification_id>/read", methods=["POST"])
def mark_notification_read(notification_id):
    """Mark a notification as read"""
    with state.lock:
        for notif in state.notifications:
            if notif.get('id') == notification_id:
                notif['read'] = True
                return jsonify({'success': True})
        return jsonify({'error': 'Notification not found'}), 404

@app.route("/api/admin/security/events/clear", methods=["POST"])
def clear_security_events():
    """Clear all security events (incident response action)"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    token_data = validate_token(token)
    
    if not token_data:
        return jsonify({"error": "Invalid or expired token"}), 403
    
    count = len(state.security_events)
    state.security_events = []
    state.failed_logins = []
    state.anomalous_data = []
    logger.info(f"🧹 Security events cleared by {token_data.get('username', 'admin')}: {count} events removed")
    # Persist cleared state
    try:
        state._save_security_events()
    except Exception:
        logger.exception('Failed to persist security events after clear')
    try:
        state._save_failed_logins()
    except Exception:
        logger.exception('Failed to persist failed logins after clear')
    try:
        state._save_anomalous_data()
    except Exception:
        logger.exception('Failed to persist anomalous data after clear')
    
    return jsonify({
        'success': True,
        'cleared': count,
        'message': f'Cleared {count} security events'
    })


@app.route("/api/admin/security/block", methods=["POST"])
def block_ip_endpoint():
    """Block an IP address and optionally revoke its tokens"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    token_data = validate_token(token, 'admin')
    if not token_data:
        return jsonify({"error": "Invalid or expired token"}), 403

    data = request.json or {}
    ip = data.get('ip')
    reason = data.get('reason')
    if not ip:
        return jsonify({'error': 'Missing ip field'}), 400

    # Block the IP
    state.block_ip(ip, blocked_by=token_data.get('username', 'admin'), reason=reason)
    # Revoke active tokens for that IP
    revoked = revoke_tokens_for_ip(ip)

    state.add_security_event('medium', 'Incident Response', f'Blocked IP {ip} and revoked {revoked} sessions', f'Reason: {reason}', 'Incident Response', ip=ip)
    return jsonify({'success': True, 'ip': ip, 'revoked_sessions': revoked})


@app.route("/api/admin/security/unblock", methods=["POST"])
def unblock_ip_endpoint():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    token_data = validate_token(token, 'admin')
    if not token_data:
        return jsonify({"error": "Invalid or expired token"}), 403

    data = request.json or {}
    ip = data.get('ip')
    if not ip:
        return jsonify({'error': 'Missing ip field'}), 400

    state.unblock_ip(ip)
    state.add_security_event('low', 'Incident Response', f'Unblocked IP {ip}', '', 'Incident Response', ip=ip)
    return jsonify({'success': True, 'ip': ip})


@app.route("/api/admin/security/blocked", methods=["GET"])
def list_blocked_ips_endpoint():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    token_data = validate_token(token, 'admin')
    if not token_data:
        return jsonify({"error": "Invalid or expired token"}), 403

    return jsonify({'blocked_ips': state.list_blocked_ips()})


@app.route("/api/admin/security/disconnect", methods=["POST"])
def disconnect_ip_endpoint():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    token_data = validate_token(token, 'admin')
    if not token_data:
        return jsonify({"error": "Invalid or expired token"}), 403

    data = request.json or {}
    ip = data.get('ip')
    if not ip:
        return jsonify({'error': 'Missing ip field'}), 400

    revoked = revoke_tokens_for_ip(ip)
    state.add_security_event('medium', 'Incident Response', f'Disconnected IP {ip} (revoked {revoked} sessions)', '', 'Incident Response', ip=ip)
    return jsonify({'success': True, 'ip': ip, 'revoked_sessions': revoked})

@app.route("/api/admin/security/acknowledge", methods=["POST"])
def acknowledge_alert():
    """Acknowledge a security alert (incident response action)"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    token_data = validate_token(token)
    
    if not token_data:
        return jsonify({"error": "Invalid or expired token"}), 403
    
    data = request.get_json()
    event_timestamp = data.get('timestamp')
    notes = data.get('notes', '')
    analyst = token_data.get('username', 'admin')
    
    # Find and mark event as acknowledged
    for event in state.security_events:
        if event['timestamp'] == event_timestamp:
            event['acknowledged'] = True
            event['acknowledged_by'] = analyst
            event['acknowledged_at'] = datetime.now().isoformat()
            event['notes'] = notes
            
            logger.info(f"✅ Alert acknowledged by {analyst}: {event['title']}")
            return jsonify({'success': True, 'event': event})
    
    return jsonify({'error': 'Event not found'}), 404


@app.route("/api/admin/security/events/create", methods=["POST"])
def create_security_event():
    """Create a new security event from client (e.g., local alarm)"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    token_data = validate_token(token)
    
    if not token_data:
        return jsonify({"error": "Invalid or expired token"}), 403
    
    data = request.get_json() or {}
    # Required fields
    severity = data.get('severity', 'medium')
    category = data.get('category', 'Unknown')
    title = data.get('title', 'Client Security Event')
    details = data.get('details', '')
    source = data.get('source', 'Client')
    timestamp = data.get('timestamp', datetime.now().isoformat())
    suspicious = data.get('suspicious', True)
    ip = data.get('ip')
    
    event = {
        'timestamp': timestamp,
        'severity': severity,
        'category': category,
        'title': title,
        'message': title,
        'details': details,
        'source': source,
        'ip': ip,
        'suspicious': suspicious
    }
    # Use add_security_event so events get saved to disk
    state.add_security_event(severity, category, title, details, source, ip)
    
    logger.info(f"New security event created by {token_data.get('username', 'admin')}: {title}")
    # Return last appended event
    return jsonify({'success': True, 'event': state.security_events[-1]}), 201

# ============================================================================
# Database Initialization
# ============================================================================
def init_database():
    """Initialize SQLite database"""
    conn = sqlite3.connect('challenge_admin.db')
    cur = conn.cursor()
    
    # Users table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')
    
    # Insert admin user
    password_hash = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()
    cur.execute('INSERT OR REPLACE INTO users (username, password) VALUES (?, ?)',
                (ADMIN_USERNAME, password_hash))
    
    # Devices table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            type TEXT,
            status TEXT,
            ip_address TEXT
        )
    ''')
    
    # Insert sample devices
    devices = [
        ('PV Inverter 1', 'inverter', 'online', '172.20.0.65'),
        ('MQTT Broker', 'broker', 'online', '172.20.0.66'),
        ('Data Logger', 'logger', 'online', '172.20.0.67'),
    ]
    
    for dev in devices:
        cur.execute('INSERT OR IGNORE INTO devices (name, type, status, ip_address) VALUES (?, ?, ?, ?)', dev)
    
    conn.commit()
    conn.close()
    logger.info("✓ Database initialized")

# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    # Initialize database
    init_database()
    
    # Create logs directory
    os.makedirs('/opt/pv-controller/logs', exist_ok=True)
    
    logger.info("=" * 60)
    logger.info("Smart Home PV Controller - CYBER RANGE MODE")
    logger.info("=" * 60)
    logger.info("✓ NO shortcuts - real attacks required!")
    logger.info("✓ ARP monitoring active")
    logger.info("✓ MQTT session tokens in traffic only")
    logger.info("✓ Phishing infrastructure ready")
    logger.info("✓ Admin dashboard requires stolen credentials")
    logger.info("=" * 60)
    
    # Start Flask app
    app.run(host="0.0.0.0", port=80, debug=False, threaded=True)
