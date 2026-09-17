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
import math
import random
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
    level=getattr(logging, os.getenv('LOG_LEVEL', 'WARNING').upper(), logging.WARNING),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

DOCUMENTS_DIR = os.getenv('DOCUMENTS_DIR', '/opt/pv-controller/Documents')
ACTION_LOGS_DIR = os.path.join(DOCUMENTS_DIR, 'actions')
TICKETS_DIR = os.path.join(DOCUMENTS_DIR, 'tickets')
HOST_HOME_LOGS_DIR = os.getenv('HOST_HOME_LOGS_DIR', '/opt/pv-controller/home-logs')
ADMIN_UI_LOG_FILE = os.path.join(HOST_HOME_LOGS_DIR, 'admin_dashboard_actions.log')


def _safe_name(value, fallback='item'):
    text = str(value or fallback).strip().lower()
    text = re.sub(r'[^a-z0-9._-]+', '_', text)
    return text[:80] or fallback


def ensure_documents_dirs():
    os.makedirs(ACTION_LOGS_DIR, exist_ok=True)
    os.makedirs(TICKETS_DIR, exist_ok=True)
    os.makedirs(HOST_HOME_LOGS_DIR, exist_ok=True)


def write_action_log(action, actor='unknown', details=None):
    ensure_documents_dirs()
    now = datetime.now()
    payload = {
        'timestamp': now.isoformat(),
        'action': action,
        'actor': actor,
        'ip': request.remote_addr if request else None,
        'method': request.method if request else None,
        'path': request.path if request else None,
        'details': details or {}
    }
    filename = f"action_{now.strftime('%Y%m%d_%H%M%S_%f')}_{_safe_name(action)}.json"
    path = os.path.join(ACTION_LOGS_DIR, filename)
    with open(path, 'w') as fh:
        json.dump(payload, fh, indent=2)
    return path


def append_admin_ui_log(action, actor='anonymous', event_type='activity', page='unknown', target=None, details=None):
    os.makedirs(os.path.dirname(ADMIN_UI_LOG_FILE), exist_ok=True)
    timestamp = datetime.now().isoformat()
    safe_details = details or {}
    parts = [
        timestamp,
        f"actor={actor}",
        f"event_type={event_type}",
        f"action={action}",
        f"page={page}",
    ]
    if target:
        parts.append(f"target={target}")
    if safe_details:
        parts.append(f"details={json.dumps(safe_details, sort_keys=True)}")
    with open(ADMIN_UI_LOG_FILE, 'a') as fh:
        fh.write(' | '.join(parts) + '\n')
    return ADMIN_UI_LOG_FILE


def write_ticket_text(ticket_type, title, body_lines):
    ensure_documents_dirs()
    now = datetime.now()
    filename = f"{_safe_name(ticket_type)}_{now.strftime('%Y%m%d_%H%M%S_%f')}_{_safe_name(title, 'ticket')}.txt"
    path = os.path.join(TICKETS_DIR, filename)
    with open(path, 'w') as fh:
        fh.write(f"Ticket Type: {ticket_type}\n")
        fh.write(f"Title: {title}\n")
        fh.write(f"Created At: {now.isoformat()}\n")
        fh.write("\n")
        for line in body_lines:
            fh.write(f"{line}\n")
    return path

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
        self.notification_seq = 0  # Monotonic counter so IDs never collide after trimming

        # Support/incident tickets shown in the admin dashboard Tickets view
        self.tickets = []
        self.ticket_seq = 0
        
        # Use RLock (reentrant lock) since add_failed_login calls add_security_event
        # while holding the lock, which would deadlock with a regular Lock
        self.lock = threading.RLock()
        # File to persist security events across page refreshes and restarts
        self.security_events_file = '/opt/pv-controller/logs/security_events.json'
        # Additional persistence files for stateful monitoring
        self.failed_logins_file = '/opt/pv-controller/logs/failed_logins.json'
        self.blocked_ips_file = '/opt/pv-controller/logs/blocked_ips.json'
        self.anomalous_data_file = '/opt/pv-controller/logs/anomalous_data.json'
        self.tickets_file = '/opt/pv-controller/logs/tickets.json'
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
        try:
            self._load_tickets()
        except Exception:
            pass

    def add_ticket(self, subject, description, reporter, source='user',
                   severity=None, category=None, ip=None):
        """Create a ticket. source is 'user' (submitted) or 'security_monitor'
        (auto-raised from a suspicious incident). Auto tickets are deduplicated
        against open tickets with the same subject to avoid flooding."""
        with self.lock:
            if source == 'security_monitor':
                for t in self.tickets:
                    if (t['source'] == 'security_monitor'
                            and t['subject'] == subject
                            and t['status'] in ('open', 'investigating')):
                        t['count'] = t.get('count', 1) + 1
                        t['last_seen'] = datetime.now().isoformat()
                        self._save_tickets_safe()
                        return t
            self.ticket_seq += 1
            ticket = {
                'id': self.ticket_seq,
                'created': datetime.now().isoformat(),
                'subject': str(subject)[:200],
                'description': str(description)[:2000],
                'reporter': str(reporter)[:80],
                'source': source,
                'severity': severity,
                'category': category,
                'ip': ip,
                'status': 'open',
                'count': 1,
                'last_seen': datetime.now().isoformat(),
            }
            self.tickets.append(ticket)
            if len(self.tickets) > 200:
                self.tickets = self.tickets[-200:]
            self._save_tickets_safe()
            return ticket

    def update_ticket_status(self, ticket_id, status):
        with self.lock:
            for t in self.tickets:
                if t['id'] == ticket_id:
                    t['status'] = status
                    self._save_tickets_safe()
                    return t
            return None

    def _save_tickets_safe(self):
        try:
            with open(self.tickets_file, 'w') as f:
                json.dump({'seq': self.ticket_seq, 'tickets': self.tickets}, f)
        except Exception:
            logger.exception('Failed to persist tickets')

    def _load_tickets(self):
        if os.path.exists(self.tickets_file):
            with open(self.tickets_file, 'r') as f:
                data = json.load(f)
            self.tickets = data.get('tickets', [])[-200:]
            self.ticket_seq = int(data.get('seq', len(self.tickets)))

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
            # Raise an HMI popup notification so the operator sees it immediately.
            # The notification 'type' mirrors the severity so the blue-team alert
            # tier filter decides which media produce audible/visual popups.
            try:
                self.notification_seq += 1
                self.notifications.append({
                    'id': self.notification_seq,
                    'timestamp': event['timestamp'],
                    'type': severity.lower(),
                    'title': f"{category}: {message}",
                    'message': details or message,
                    'read': False,
                })
                if len(self.notifications) > 20:
                    self.notifications = self.notifications[-20:]
            except Exception:
                logger.exception("Failed to raise HMI notification for security event")
            # Suspicious incidents automatically raise a ticket for admin triage
            if event['suspicious']:
                try:
                    self.add_ticket(
                        subject=message,
                        description=details or message,
                        reporter=source or 'Security Monitor',
                        source='security_monitor',
                        severity=severity,
                        category=category,
                        ip=ip,
                    )
                except Exception:
                    logger.exception('Failed to auto-create incident ticket')
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
                json.dump(self.security_events, fh, separators=(',', ':'))
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
                json.dump(self.failed_logins, fh, separators=(',', ':'))
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
                json.dump(self.blocked_ips, fh, separators=(',', ':'))
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
                json.dump(self.anomalous_data, fh, separators=(',', ':'))
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
ADMIN_PASSWORD = "admin123"
WIFI_PASSWORD = "super-secret-123"     # Discovered via /wifi_scan, but NOT admin password

# Blue team operator credentials
BLUETEAM_USERNAME = "blueteam"
BLUETEAM_PASSWORD = "blueTeam123"

# Persist a user-chosen blue-team password across restarts. Loaded at startup,
# written by the "change password" endpoint. Stored in the same directory so it
# survives container restarts unless the state volume is wiped.
BLUETEAM_CRED_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'blueteam_credentials.json')

def _load_blueteam_password():
    global BLUETEAM_PASSWORD
    try:
        if os.path.exists(BLUETEAM_CRED_FILE):
            with open(BLUETEAM_CRED_FILE, 'r') as f:
                data = json.load(f)
            stored = data.get('password')
            if stored and isinstance(stored, str) and len(stored) >= 6:
                BLUETEAM_PASSWORD = stored
    except Exception:
        logger.exception('Failed to load blue-team credentials')

def _save_blueteam_password(password):
    try:
        with open(BLUETEAM_CRED_FILE, 'w') as f:
            json.dump({'username': BLUETEAM_USERNAME, 'password': password}, f)
    except Exception:
        logger.exception('Failed to persist blue-team credentials')

_load_blueteam_password()

# Persist a rotated admin password the same way, so a blue-team credential
# reset survives container restarts.
ADMIN_CRED_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'admin_credentials.json')

def _load_admin_password():
    global ADMIN_PASSWORD
    try:
        if os.path.exists(ADMIN_CRED_FILE):
            with open(ADMIN_CRED_FILE, 'r') as f:
                data = json.load(f)
            stored = data.get('password')
            if stored and isinstance(stored, str) and len(stored) >= 6:
                ADMIN_PASSWORD = stored
    except Exception:
        logger.exception('Failed to load admin credentials')

def _save_admin_password(password):
    try:
        with open(ADMIN_CRED_FILE, 'w') as f:
            json.dump({'username': ADMIN_USERNAME, 'password': password}, f)
    except Exception:
        logger.exception('Failed to persist admin credentials')

_load_admin_password()

# ── Blue-team defense state ──────────────────────────────────────────────
# Populated when the defender logs in; cleared on logout so the system
# reverts to insecure defaults — matching the training scenario design.
BLUETEAM_DEFAULT_SETTINGS = {
    'login_rate_limit': False,
    'rate_limit_per_minute': 5,
    'modbus_write_restricted': False,
    'telemetry_validation': False,
    'telemetry_max_power_kw': 10.0,
    'telemetry_min_power_kw': -2.0,
    'xss_protection': False,
    'ip_whitelist_enabled': False,
    'ip_whitelist': [],
    'admin_session_timeout_minutes': 30,
    'alert_notification_tier': 'critical',
    'blocked_ips_manual': [],
    'ip_blacklist_enabled': False,
    'ip_blacklist': [],
    'inactivity_timeout_minutes': 5,
}

# Built-in mitigation signatures used when the blue team enables a control.
# These replace any user-written code: enabling a control applies the canned
# detection rule directly so the training stays hands-on without writing code.
XSS_BLOCK_PATTERNS = [
    re.compile(r'<\s*script', re.I),
    re.compile(r'on\w+\s*=', re.I),
    re.compile(r'javascript\s*:', re.I),
    re.compile(r'<\s*(iframe|object|embed|svg)\b', re.I),
    re.compile(r'--\s*-', re.I),
    re.compile(r'union\s+select', re.I),
]

blueteam_defense = {
    'active': False,
    'active_since': 0.0,
    'settings': dict(BLUETEAM_DEFAULT_SETTINGS),
    'last_activity': time.time(),
    'active_token': None,
}
_blueteam_login_ts: list = []   # timestamps for rate-limit window

pv_status = {
    "status": "RUNNING",
    "power_kw": 3.2,
    "voltage_v": 240,
    "current_a": 13.3,
    "last_update": time.time()
}

SERVER_STARTED_AT = time.time()

# ============================================================================
# PV OUTPUT SIMULATION
# Realistic residential solar curve: follows daylight hours with smooth cloud
# noise so dashboards show believable production instead of a flat value.
# ============================================================================

PV_CAPACITY_KW = 4.8
SUNRISE_HOUR = 6.5   # local time
SUNSET_HOUR = 19.5   # local time
_cloud_state = {'value': 0.0, 'last': 0.0}

def solar_elevation_factor(now=None):
    """Return 0..1 daylight factor for the simulated site."""
    lt = time.localtime(now if now is not None else time.time())
    hours = lt.tm_hour + lt.tm_min / 60.0 + lt.tm_sec / 3600.0
    if hours <= SUNRISE_HOUR or hours >= SUNSET_HOUR:
        return 0.0
    x = (hours - SUNRISE_HOUR) / (SUNSET_HOUR - SUNRISE_HOUR)
    return max(0.0, math.sin(math.pi * x) ** 1.35)

def compute_pv_power(now=None):
    """Simulated PV output in kW (daylight curve + slow cloud noise)."""
    if pv_status.get('status') != 'RUNNING':
        return 0.0
    tnow = now if now is not None else time.time()
    elev = solar_elevation_factor(tnow)
    if elev <= 0.0:
        return round(random.uniform(0.0, 0.04), 3)
    # Smooth cloud noise: bounded random walk sampled at most once per second
    if tnow - _cloud_state['last'] >= 1.0 or _cloud_state['last'] == 0.0:
        _cloud_state['value'] += random.uniform(-0.045, 0.045)
        _cloud_state['value'] = max(-0.14, min(0.14, _cloud_state['value']))
        _cloud_state['last'] = tnow
    base = PV_CAPACITY_KW * elev * (1.0 + _cloud_state['value'])
    return round(max(0.0, base), 3)

# Compatibility state for legacy helper tooling
replayer_state = {'running': False, 'last_played': None}
mqtt_series = []

# JWT-like tokens with expiration
active_tokens = {}  # token -> {username, expires, type}

# MQTT session token (changes periodically, visible only in network traffic)
MQTT_SESSION_TOKEN = f"mqtt-session-{secrets.token_hex(8)}"
MQTT_TELEMETRY_INTERVAL = max(1.0, float(os.getenv('MQTT_TELEMETRY_INTERVAL', '3')))
MQTT_STATUS_INTERVAL = max(10, int(os.getenv('MQTT_STATUS_INTERVAL', '30')))

def generate_token(username, token_type='api', expires_in=1800, ip_address=None, role=None):
    """Generate token with expiration (30 min default)"""
    token = secrets.token_urlsafe(32)
    active_tokens[token] = {
        'username': username,
        'type': token_type,
        'role': role or token_type,
        'expires': time.time() + expires_in,
        'created': time.time()
    }
    # Store the originating IP (if provided) for token revocation / block enforcement
    if ip_address:
        active_tokens[token]['ip'] = ip_address
    return token


def touch_blueteam_activity():
    """Record blue-team activity so the auto-logout timer never fires while busy."""
    if blueteam_defense['active']:
        blueteam_defense['last_activity'] = time.time()


def blueteam_inactivity_expired():
    """Return True if the blue team has been inactive beyond the timeout."""
    if not blueteam_defense['active']:
        return False
    timeout_min = int(blueteam_defense['settings'].get('inactivity_timeout_minutes', 5))
    return (time.time() - blueteam_defense['last_activity']) > timeout_min * 60


def blueteam_auto_logout():
    """Force the blue-team session to end and reset all defenses."""
    blueteam_defense['active'] = False
    blueteam_defense['active_since'] = 0.0
    blueteam_defense['settings'] = dict(BLUETEAM_DEFAULT_SETTINGS)
    _blueteam_login_ts.clear()
    token = blueteam_defense.get('active_token')
    if token and token in active_tokens:
        del active_tokens[token]
    blueteam_defense['active_token'] = None
    logger.info("🔒 Blue-team session auto-expired (inactivity) — defenses reset")
    try:
        write_action_log('blueteam_auto_logout',
                         actor='blueteam', details={'reason': 'inactivity_timeout'})
    except Exception:
        pass


def ip_matches(ip, allowlist):
    """Return True if ip matches any exact value or CIDR prefix in allowlist."""
    for entry in allowlist:
        entry = str(entry or '').strip()
        if not entry:
            continue
        if entry == ip:
            return True
        if '/' in entry:
            prefix, plen = entry.split('/', 1)
            try:
                plen = int(plen)
            except ValueError:
                continue
            if ip.startswith(prefix + '.'):
                if ip.split('.')[:2] == prefix.split('.')[:2]:
                    return True
            try:
                import ipaddress as _ipa
                if _ipa.ip_address(ip) in _ipa.ip_network(entry, strict=False):
                    return True
            except ValueError:
                pass
        elif ip.startswith(entry + '.'):
            return True
    return False


def is_ip_blacklisted(ip):
    """Manual IP blacklist check (exact IPs, prefixes, or CIDR subnets)."""
    settings = blueteam_defense['settings']
    if not (blueteam_defense['active'] and settings.get('ip_blacklist_enabled')):
        return False
    return ip_matches(ip, settings.get('ip_blacklist', []))


def ip_is_whitelisted(ip):
    """IP whitelist check against the configured allowlist."""
    settings = blueteam_defense['settings']
    if not (blueteam_defense['active'] and settings.get('ip_whitelist_enabled')):
        return True
    return ip_matches(ip, settings.get('ip_whitelist', []))


def request_has_xss_or_sqli(path, query, body):
    """Built-in XSS / SQLi signature check (no user code required)."""
    blob = f"{path} {query} {body}".lower()
    for pat in XSS_BLOCK_PATTERNS:
        if pat.search(blob):
            return True
    if re.search(r"'\s*(or|and)\s*'?1'?\s*=\s*'?1", blob):
        return True
    return False


@app.before_request
def defense_middleware():
    """Global blue-team defensive middleware applied to /api/ requests."""
    if not request.path.startswith('/api/'):
        return None
    remote = request.remote_addr or ''
    active = blueteam_defense['active']
    settings = blueteam_defense['settings']
    # The login endpoint is always reachable as the recovery path — the
    # blue team can log back in to fix a misconfiguration even if they
    # accidentally lock out their own IP.
    is_login = request.path == '/api/admin/login'
    # The blue-team control API is likewise always reachable. Otherwise
    # enabling the IP whitelist/blacklist would block the very request that
    # saves the setting (self-lockout) and the console could not be recovered.
    is_control = request.path.startswith('/api/blueteam/')
    ip_gate_exempt = is_login or is_control

    # ── IP blacklist (manual list) ────────────────────────────────────────
    if (active and settings.get('ip_blacklist_enabled')
            and is_ip_blacklisted(remote) and not ip_gate_exempt):
        state.add_security_event('high', 'Network Access',
                                 f'Blacklisted IP {remote} blocked from API',
                                 'Request rejected by blue-team IP blacklist',
                                 'Blue Team Defense', ip=remote)
        return jsonify({'error': 'Access denied'}), 403

    # ── IP whitelist (allowlist matcher) ─────────────────────────────────
    if (active and settings.get('ip_whitelist_enabled')
            and not ip_is_whitelisted(remote) and not ip_gate_exempt):
        state.add_security_event('medium', 'Network Access',
                                 f'Non-whitelisted IP {remote} blocked from API',
                                 'Request rejected by blue-team IP whitelist',
                                 'Blue Team Defense', ip=remote)
        return jsonify({'error': 'IP not whitelisted'}), 403

    # ── XSS / SQLi filter (built-in signatures) ──────────────────────────
    if active and settings.get('xss_protection') and not request.path.startswith('/api/blueteam/'):
        payload = ''
        if request.is_json:
            data = request.get_json(silent=True) or {}
            payload = json.dumps(data)
        elif request.form:
            payload = request.form.to_dict(flat=False).values().__repr__()
        query = request.query_string.decode('utf-8', 'ignore')
        if request_has_xss_or_sqli(request.path, query, payload):
            try:
                write_action_log('xss_attempt_blocked',
                                 actor='defense',
                                 details={'path': request.path, 'ip': remote})
            except Exception:
                pass
            state.add_security_event(
                'medium', 'Web Application Security',
                'Request blocked by blue-team web filter',
                f'Path {request.path} from {remote} rejected by security filter',
                'Blue Team Defense', ip=remote
            )
            return jsonify({'error': 'Request blocked by security filter'}), 400
    return None


def validate_token(token, required_type=None):
    """Validate token and check expiration"""
    token_data = active_tokens.get(token)
    if not token_data:
        return None
    
    if token_data['expires'] < time.time():
        del active_tokens[token]
        return None

    # ── Blue-team inactivity auto-logout ──────────────────────────────────
    if token_data.get('role') == 'blueteam':
        if blueteam_inactivity_expired():
            blueteam_auto_logout()
            return None
        # Any use of the token counts as activity (refreshes the timer)
        blueteam_defense['last_activity'] = time.time()

    # ── Blue-team admin session timeout enforcement ──────────────────────
    # The cap counts from the later of the session's creation and the moment
    # blue-team defenses were activated. A pre-existing admin session is
    # therefore given the configured grace period from the point the control
    # was armed instead of being killed instantly mid-task, while lingering
    # sessions are still eventually forced to re-authenticate.
    if (blueteam_defense['active']
            and token_data.get('role') == 'admin'):
        timeout_min = int(blueteam_defense['settings'].get('admin_session_timeout_minutes', 30))
        created = token_data.get('created', 0)
        active_since = blueteam_defense.get('active_since', 0) or 0
        effective_start = max(created, active_since)
        if time.time() - effective_start > timeout_min * 60:
            del active_tokens[token]
            logger.info("Admin session expired via blue-team timeout policy")
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
            
            # ── TELEMETRY VALIDATION (blue-team defensive control) ─────────
            # When enabled, drops messages whose power reading is non-numeric or
            # falls outside the configured safe physical bounds.
            if (blueteam_defense['active']
                    and blueteam_defense['settings'].get('telemetry_validation')):
                within = True
                if power is not None:
                    if not isinstance(power, (int, float)):
                        within = False
                    else:
                        hi = blueteam_defense['settings'].get('telemetry_max_power_kw', 10.0)
                        lo = blueteam_defense['settings'].get('telemetry_min_power_kw', -2.0)
                        if not (lo <= float(power) <= hi):
                            within = False
                if not within:
                    logger.info("Blue-team telemetry validation dropped message")
                    state.add_security_event(
                        'high', 'Data Integrity',
                        'Malformed telemetry blocked by validation',
                        f'Payload rejected by telemetry limits: {json.dumps(payload)[:80]}',
                        'Blue Team Defense'
                    )
                    return  # refuse to ingest attacker injection
            
            # Detect malformed data (type confusion attacks)
            if power is not None and not isinstance(power, (int, float)):
                # Throttle malformed events to avoid flooding: at most one per 60 seconds
                now = datetime.now()
                last = getattr(state, 'last_malformed_time', None)
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

            elif command == 'RESET':
                reset_pv_plant(actor='MQTT operator', via='MQTT')
                logger.info("♻️ PV SYSTEM RESET VIA MQTT")
                
    except Exception as e:
        logger.error(f"MQTT message error: {e}")

def publish_mqtt_status():
    """Publish system status to MQTT (includes session token in metadata)"""
    if mqtt_client and mqtt_client.is_connected():
        status_msg = {
            'status': pv_status['status'],
            'power_kw': pv_status['power_kw'],
            'voltage_v': pv_status.get('voltage_v', 240),
            'current_a': pv_status.get('current_a', 0),
            'uptime_s': int(time.time() - SERVER_STARTED_AT),
            'timestamp': time.time(),
            'session': MQTT_SESSION_TOKEN  # Only visible in packet capture!
        }
        mqtt_client.publish('pv/status', json.dumps(status_msg), qos=1)

def mqtt_telemetry_thread():
    """Publish telemetry data periodically"""
    global mqtt_series
    last_status_publish = 0.0
    while True:
        try:
            if mqtt_client and mqtt_client.is_connected():
                power_kw = compute_pv_power()
                voltage_v = round(239.5 + random.uniform(-2.5, 2.5), 1)
                current_a = round((power_kw * 1000.0 / max(1, voltage_v)), 2) if power_kw > 0 else 0.0
                telemetry = {
                    'power_kw': power_kw,
                    'voltage_v': voltage_v,
                    'current_a': current_a,
                    'timestamp': time.time()
                }
                # Keep the shared status consistent so /api/status and MQTT
                # status messages reflect the same simulated plant state
                pv_status['power_kw'] = power_kw
                pv_status['voltage_v'] = voltage_v
                pv_status['current_a'] = current_a
                pv_status['last_update'] = telemetry['timestamp']
                mqtt_client.publish('pv/telemetry', json.dumps(telemetry), qos=0)
                mqtt_series.append({
                    'ts': telemetry['timestamp'],
                    'value': telemetry['power_kw'],
                    'power': telemetry['power_kw']
                })
                if len(mqtt_series) > 600:
                    mqtt_series = mqtt_series[-600:]
                
                # Occasionally publish status (with session token)
                now = time.time()
                if now - last_status_publish >= MQTT_STATUS_INTERVAL:
                    publish_mqtt_status()
                    last_status_publish = now
            
            time.sleep(MQTT_TELEMETRY_INTERVAL)
        except Exception as e:
            logger.error(f"Telemetry error: {e}")
            time.sleep(max(2.0, MQTT_TELEMETRY_INTERVAL))

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
                    # Blue-team protection: if write protection armed, refuse to halt
                    if (blueteam_defense['active']
                            and blueteam_defense['settings'].get('modbus_write_restricted')):
                        logger.info("🔒 Blue-team Modbus protection prevented HALT via monitor")
                        state.add_security_event(
                            'high', 'ICS Protocol',
                            'Modbus HALT attempt BLOCKED by protection',
                            'Coil 1 write rejected by defense control',
                            'Blue Team Defense'
                        )
                    else:
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

class GuardedCoilBlock(ModbusSequentialDataBlock):
    """Coil store that physically drops the HALT write when blue-team Modbus
    write protection is armed.

    pymodbus has no write callback hook, so writes are intercepted by wrapping
    the coil datablock. When the control is active, a write that sets coil 1
    TRUE is refused before it ever reaches the plant; the traffic is still
    flagged as a security event so the blue team can attribute the attempt.
    """

    def setValues(self, address, values):
        # pymodbus offsets device addresses by +1 into the datastore, so the
        # HALT coil (device coil 1) lives at block index 2 even though callers
        # address it as 1.
        if isinstance(values, (list, tuple)):
            touched = range(address, address + len(values))
            any_true = any(v not in (0, False) for v in values)
        else:
            touched = range(address, address + 1)
            any_true = values not in (0, False)
        if (2 in touched and any_true
                and blueteam_defense['active']
                and blueteam_defense['settings'].get('modbus_write_restricted')):
            logger.info("🔒 Blue-team Modbus write protection blocked HALT write")
            state.add_security_event(
                'high', 'ICS Protocol',
                'Modbus HALT write BLOCKED by protection',
                f'Write to coil 1 (TRUE) rejected at datastore — defense control active',
                'Blue Team Defense'
            )
            return  # do NOT land the write, do NOT halt the plant
        return super().setValues(address, values)


def reset_pv_plant(actor='operator', via='HMI'):
    """Restore a halted PV plant to RUNNING after an incident.

    Clears the Modbus HALT coil and resets the plant status so telemetry
    resumes. Records the action as a security event + HMI notification so the
    recovery is visible to both teams.
    """
    global modbus_context
    pv_status['status'] = 'RUNNING'
    pv_status['power_kw'] = 0.0  # repopulated by the telemetry thread momentarily

    # Clear coil 1 so the monitor doesn't re-trigger the halt on the next poll
    # and the plant state matches a fresh boot.
    try:
        if modbus_context is not None:
            modbus_context[0].setValues(1, 1, [False])
    except Exception:
        logger.exception('Failed to clear Modbus coil 1 during plant reset')

    state.add_security_event(
        'low', 'System Control',
        f'PV plant reset to RUNNING ({via})',
        f'Plant restored after halt by {actor}',
        'Plant Controller'
    )
    try:
        write_action_log('plant_reset', actor=actor, details={'status': 'RUNNING', 'via': via})
    except Exception:
        logger.exception('Failed to write plant_reset action log')
    logger.info(f"♻️ PV plant reset to RUNNING by {actor} via {via}")

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
            co=GuardedCoilBlock(0, [0]*100),            # Coils (write-protected)
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
    Admin / Blue-team login.
    Returns a role-aware token so the front-end can branch views.
    """
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    client_ip = request.remote_addr
    
    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400
    
    # ── IP block check ─────────────────────────────────────────────────
    if state.is_blocked(client_ip):
        try:
            write_action_log('admin_login_blocked', actor=username or 'unknown', details={'ip': client_ip})
        except Exception:
            logger.exception('Failed to write action log for blocked login')
        logger.warning(f"Blocked IP {client_ip} attempted login")
        state.add_security_event('medium', 'Authentication', 'Blocked IP attempted admin login', f'IP: {client_ip}', 'Authentication Service', ip=client_ip)
        return jsonify({"error": "Access denied"}), 403

    # ── Credential check ───────────────────────────────────────────────
    is_blueteam = (username == BLUETEAM_USERNAME and password == BLUETEAM_PASSWORD)
    is_admin     = (username == ADMIN_USERNAME  and password == ADMIN_PASSWORD)

    # ── Blue-team rate-limit (only active when blueteam is logged in) ───
    # Throttles brute-force (invalid) attempts only; operators with valid
    # admin/blueteam credentials are never locked out by the limiter.
    if (not (is_admin or is_blueteam)
            and blueteam_defense['active']
            and blueteam_defense['settings'].get('login_rate_limit')):
        now = time.time()
        window = 60
        _blueteam_login_ts[:] = [t for t in _blueteam_login_ts if now - t < window]
        if len(_blueteam_login_ts) >= blueteam_defense['settings'].get('rate_limit_per_minute', 5):
            state.add_security_event('high', 'Rate Limiting',
                                     f'Login rate limit triggered from {client_ip}',
                                     f'{len(_blueteam_login_ts)} attempts in {window}s',
                                     'Blue Team Defense', ip=client_ip)
            return jsonify({"error": "Rate limit exceeded – try again later"}), 429
        _blueteam_login_ts.append(now)

    if is_blueteam:
        # Activate defense system when defender logs in. Settings created in a
        # prior session are reset only on logout, so a re-login does not wipe
        # changes that were never properly logged off.
        if not blueteam_defense['active']:
            blueteam_defense['settings'] = dict(BLUETEAM_DEFAULT_SETTINGS)
        blueteam_defense['active'] = True
        blueteam_defense['active_since'] = time.time()
        blueteam_defense['last_activity'] = time.time()
        token = generate_token(username, 'blueteam', expires_in=3600, ip_address=client_ip, role='blueteam')
        blueteam_defense['active_token'] = token
        try:
            write_action_log('blueteam_login_success', actor=username, details={'ip': client_ip})
        except Exception:
            logger.exception('Failed to write action log for blueteam login')
        state.add_security_event('low', 'Authentication',
                                 f'Blue team operator logged in from {client_ip}',
                                 'Defense system activated', 'Authentication Service', ip=client_ip)
        logger.info(f"✓ Blue team authenticated: {username}")
        return jsonify({"token": token, "username": username, "role": "blueteam", "expires_in": 3600})

    if is_admin:
        # Deactivate blue-team defenses when admin logs in (admin overrides)
        blueteam_defense['active'] = False
        blueteam_defense['active_since'] = 0.0
        blueteam_defense['settings'] = dict(BLUETEAM_DEFAULT_SETTINGS)
        token = generate_token(username, 'admin', expires_in=1800, ip_address=client_ip, role='admin')
        try:
            write_action_log('admin_login_success', actor=username, details={'ip': client_ip})
        except Exception:
            logger.exception('Failed to write action log for successful login')
        state.mark_event('admin_authenticated', {'username': username})
        state.add_security_event('medium', 'Authentication',
                                 f'Admin login successful from {client_ip}',
                                 f'User {username} authenticated successfully',
                                 'Authentication Service', ip=client_ip)
        logger.info(f"✓ Admin authenticated: {username}")
        return jsonify({"token": token, "username": username, "role": "admin", "expires_in": 1800})
    
    # Track failed login
    try:
        write_action_log('admin_login_failed', actor=username or 'unknown', details={'ip': client_ip})
    except Exception:
        logger.exception('Failed to write action log for failed login')
    state.add_failed_login(username, client_ip)
    logger.warning(f"Failed admin login attempt: {username} from {client_ip}")
    return jsonify({"error": "Invalid credentials"}), 401


# ============================================================================
# BLUE TEAM DEFENSE ENDPOINTS
# ============================================================================

def _validate_blueteam_token(token):
    """Return token_data if valid blue-team token, else None."""
    data = validate_token(token)
    if data and data.get('role') == 'blueteam':
        return data
    return None


@app.route('/api/blueteam/settings', methods=['GET'])
def blueteam_get_settings():
    token = request.headers.get('Authorization', '').removeprefix('Bearer ').strip()
    if not _validate_blueteam_token(token):
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({
        'active': blueteam_defense['active'],
        'settings': blueteam_defense['settings'],
        'inactivity_timeout_minutes': blueteam_defense['settings'].get('inactivity_timeout_minutes', 5),
        'last_activity': blueteam_defense['last_activity'],
    })


@app.route('/api/blueteam/settings', methods=['PUT'])
def blueteam_update_settings():
    token = request.headers.get('Authorization', '').removeprefix('Bearer ').strip()
    if not _validate_blueteam_token(token):
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    settings = blueteam_defense['settings']

    # Whitelist of keys that the blue team is allowed to change
    allowed_keys = set(BLUETEAM_DEFAULT_SETTINGS.keys())
    for key, value in data.items():
        if key not in allowed_keys:
            continue
        # Coerce to expected type
        default = BLUETEAM_DEFAULT_SETTINGS[key]
        if isinstance(default, bool):
            settings[key] = bool(value)
        elif isinstance(default, (int, float)):
            settings[key] = type(default)(value)
        elif isinstance(default, list):
            settings[key] = list(value)
        else:
            settings[key] = value

    blueteam_defense['active'] = True
    touch_blueteam_activity()
    logger.info(f"Blue-team defense updated: {list(data.keys())}")
    try:
        write_action_log('blueteam_settings_updated',
                         actor='blueteam',
                         details={'updated_keys': list(data.keys())})
    except Exception:
        pass
    return jsonify({'status': 'ok', 'settings': settings})


@app.route('/api/blueteam/logout', methods=['POST'])
def blueteam_logout():
    """Clear all blue-team defenses — system reverts to insecure defaults."""
    token = request.headers.get('Authorization', '').removeprefix('Bearer ').strip()
    token_data = active_tokens.get(token)
    is_bt = token_data and token_data.get('role') == 'blueteam'
    # Also accept admin calling this to force-reset
    is_admin = token_data and token_data.get('role') == 'admin'
    if not is_bt and not is_admin:
        return jsonify({'error': 'Unauthorized'}), 401

    blueteam_auto_logout()
    logger.info("Blue-team defense reset — system reverted to insecure defaults")
    try:
        write_action_log('blueteam_logout_reset',
                         actor=token_data.get('username', 'unknown'),
                         details={'status': 'all_defenses_cleared'})
    except Exception:
        pass
    # The auto_logout already revokes the stored blueteam token; revoke this one too
    if token in active_tokens and active_tokens[token].get('role') == 'blueteam':
        del active_tokens[token]
    return jsonify({'status': 'reset'})


@app.route('/api/blueteam/change-password', methods=['POST'])
def blueteam_change_password():
    """Let the blue-team operator rotate their own credential."""
    global BLUETEAM_PASSWORD
    token = request.headers.get('Authorization', '').replace('Bearer ', '').strip()
    token_data = active_tokens.get(token)
    if not token_data or token_data.get('role') != 'blueteam':
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json or {}
    current = data.get('current_password') or ''
    new_pw = data.get('new_password') or ''
    confirm = data.get('confirm_password')

    if current != BLUETEAM_PASSWORD:
        state.add_security_event('medium', 'Authentication',
                                 'Blue team password change rejected (wrong current password)',
                                 'Incorrect current password supplied',
                                 'Blue Team Authentication')
        return jsonify({'error': 'Current password is incorrect'}), 400

    if len(new_pw) < 6:
        return jsonify({'error': 'New password must be at least 6 characters'}), 400

    if confirm is not None and new_pw != confirm:
        return jsonify({'error': 'New password confirmation does not match'}), 400

    if new_pw == BLUETEAM_PASSWORD:
        return jsonify({'error': 'New password must differ from the current password'}), 400

    BLUETEAM_PASSWORD = new_pw
    _save_blueteam_password(new_pw)
    state.add_security_event('high', 'Authentication',
                             'Blue team operator password was changed',
                             'Blue team credential rotated',
                             'Blue Team Authentication')
    try:
        write_action_log('blueteam_password_changed',
                         actor=token_data.get('username', 'blueteam'),
                         details={'status': 'success'})
    except Exception:
        logger.exception('Failed to write password-change action log')
    logger.info("Blue team operator changed their password")
    return jsonify({'status': 'ok', 'message': 'Password updated'})


@app.route('/api/blueteam/users', methods=['GET'])
def blueteam_list_users():
    """List operator accounts for the blue-team Users tab."""
    token = request.headers.get('Authorization', '').removeprefix('Bearer ').strip()
    if not _validate_blueteam_token(token):
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'users': [
        {'username': ADMIN_USERNAME, 'role': 'admin',
         'description': 'HMI administrator — full SCADA dashboard access'},
        {'username': BLUETEAM_USERNAME, 'role': 'blueteam',
         'description': 'Blue team operator — defense console access'},
    ]})


@app.route('/api/blueteam/users/change-password', methods=['POST'])
def blueteam_user_change_password():
    """Blue-team privilege: reset any operator account's password."""
    global ADMIN_PASSWORD, BLUETEAM_PASSWORD
    token = request.headers.get('Authorization', '').removeprefix('Bearer ').strip()
    token_data = _validate_blueteam_token(token)
    if not token_data:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json or {}
    username = (data.get('username') or '').strip()
    new_pw = data.get('new_password') or ''
    confirm = data.get('confirm_password')

    if username not in (ADMIN_USERNAME, BLUETEAM_USERNAME):
        return jsonify({'error': 'Unknown user'}), 404
    if len(new_pw) < 6:
        return jsonify({'error': 'New password must be at least 6 characters'}), 400
    if confirm is not None and new_pw != confirm:
        return jsonify({'error': 'New password confirmation does not match'}), 400

    if username == ADMIN_USERNAME:
        if new_pw == ADMIN_PASSWORD:
            return jsonify({'error': 'New password must differ from the current password'}), 400
        ADMIN_PASSWORD = new_pw
        _save_admin_password(new_pw)
    else:
        if new_pw == BLUETEAM_PASSWORD:
            return jsonify({'error': 'New password must differ from the current password'}), 400
        BLUETEAM_PASSWORD = new_pw
        _save_blueteam_password(new_pw)

    state.add_security_event('high', 'Authentication',
                             f'Password reset for user: {username}',
                             'Credential rotated via blue-team Users console',
                             'Blue Team Authentication')
    try:
        write_action_log('blueteam_user_password_reset',
                         actor=token_data.get('username', 'blueteam'),
                         details={'target_user': username, 'status': 'success'})
    except Exception:
        logger.exception('Failed to write user password-reset action log')
    logger.info(f"Blue team reset password for user: {username}")
    return jsonify({'status': 'ok', 'message': f'Password updated for {username}'})


@app.route('/api/blueteam/defense_status')
def blueteam_defense_status():
    """Public endpoint so the HMI can show 'Defenses Active' banner."""
    return jsonify({
        'active': blueteam_defense['active'],
        'controls_enabled': sum(1 for k, v in blueteam_defense['settings'].items()
                                if isinstance(v, bool) and v and k != 'login_rate_limit'),
        'alert_tier': blueteam_defense['settings'].get('alert_notification_tier', 'low'),
        'inactivity_timeout_minutes': blueteam_defense['settings'].get('inactivity_timeout_minutes', 5),
        'telemetry_validation': bool(
            blueteam_defense['active']
            and blueteam_defense['settings'].get('telemetry_validation')),
        'telemetry_min_kw': blueteam_defense['settings'].get('telemetry_min_power_kw', -2.0),
        'telemetry_max_kw': blueteam_defense['settings'].get('telemetry_max_power_kw', 10.0),
        'modbus_write_restricted': bool(
            blueteam_defense['active']
            and blueteam_defense['settings'].get('modbus_write_restricted')),
    })


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


@app.route('/api/admin/activity', methods=['POST'])
def admin_activity_log():
    """Append sanitized admin dashboard UI activity to a .log file."""
    auth_header = request.headers.get('Authorization', '')
    token_data = None

    if auth_header.startswith('Bearer '):
        token = auth_header.split(' ', 1)[1]
        token_data = validate_token(token)
        # Both the admin HMI and the blue-team console log their actions to the
        # same audit trail, so either operator role is acceptable here.
        if not token_data or token_data.get('role') not in ('admin', 'blueteam'):
            return jsonify({'error': 'Invalid or expired token'}), 403

    data = request.json or {}
    action = str(data.get('action') or 'unknown_action')[:120]
    event_type = str(data.get('event_type') or 'activity')[:80]
    page = str(data.get('page') or 'unknown')[:120]
    target = data.get('target')
    if target is not None:
        target = str(target)[:160]

    details = data.get('details') or {}
    if not isinstance(details, dict):
        details = {'value': str(details)[:500]}

    allowed_detail_keys = {
        'component',
        'control',
        'destination',
        'field',
        'field_type',
        'form',
        'href',
        'label',
        'method',
        'outcome',
        'result',
        'section',
        'selection',
        'state',
        'status',
        'value',
        'view',
        'notification_id',
        'ip',
        'notes_present',
        'filename',
        'count',
        'address',
        'register',
    }
    sanitized_details = {}
    for key, value in details.items():
        if key not in allowed_detail_keys:
            continue
        if isinstance(value, (dict, list, tuple)):
            sanitized_details[key] = json.dumps(value)[:500]
        elif isinstance(value, (str, int, float, bool)) or value is None:
            sanitized_details[key] = value if value is None else str(value)[:500]

    actor = str(data.get('actor') or (token_data or {}).get('username') or 'anonymous')[:80]
    client_ip = request.remote_addr or 'unknown'
    sanitized_details.setdefault('ip', client_ip)
    sanitized_details.setdefault('method', request.method)

    try:
        log_path = append_admin_ui_log(
            action=action,
            actor=actor,
            event_type=event_type,
            page=page,
            target=target,
            details=sanitized_details,
        )
    except Exception:
        logger.exception('Failed to append admin UI activity log')
        return jsonify({'error': 'Failed to write log'}), 500

    return jsonify({'result': 'ok', 'log_file': log_path})

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
        "uptime_s": int(time.time() - SERVER_STARTED_AT),
        "mqtt_connected": mqtt_client.is_connected() if mqtt_client else False
    })


@app.route("/status")
def status_compat():
    """Legacy status endpoint compatibility."""
    return jsonify({
        "status": pv_status['status'],
        "power": int(pv_status.get('power_kw', 0) * 1000),
        "power_kw": pv_status['power_kw'],
        "voltage_v": pv_status['voltage_v'],
        "current_a": pv_status['current_a'],
        "uptime_s": int(time.time() - SERVER_STARTED_AT),
        "mqtt_session": MQTT_SESSION_TOKEN,
        "last_update": pv_status['last_update']
    })


@app.route("/api/plant/reset", methods=['POST'])
def api_plant_reset():
    """Operator recovery action: bring a halted plant back to RUNNING.

    Available to any authenticated operator (admin or blue team) so the plant
    can be restored after an incident without a full container restart.
    """
    token = request.headers.get('Authorization', '').replace('Bearer ', '').strip()
    token_data = validate_token(token)
    if not token_data:
        return jsonify({'error': 'Invalid or expired token'}), 401

    actor = token_data.get('username', 'operator')
    reset_pv_plant(actor=actor, via='HMI')
    return jsonify({'success': True, 'status': pv_status['status']})


_net_counters_lock = threading.Lock()
_net_counters_prev = {'rx': 0, 'tx': 0, 't': 0.0}


def _read_host_metrics():
    """Collect real host metrics from /proc (Linux) with graceful fallbacks."""
    # --- CPU utilisation (sample /proc/stat twice) ---
    cpu_pct = None
    try:
        def _cpu_snapshot():
            with open('/proc/stat') as f:
                parts = f.readline().split()[1:]
            return [int(v) for v in parts]

        t1 = _cpu_snapshot()
        time.sleep(0.12)
        t2 = _cpu_snapshot()
        deltas = [b - a for a, b in zip(t1, t2)]
        total = sum(deltas)
        idle = deltas[3] + (deltas[4] if len(deltas) > 4 else 0)
        if total > 0:
            cpu_pct = round(100.0 * (total - idle) / total, 1)
    except Exception:
        pass

    # --- Memory ---
    mem_pct = None
    mem_used_mb = mem_total_mb = 0
    try:
        info = {}
        for line in open('/proc/meminfo'):
            key, val = line.split(':', 1)
            info[key.strip()] = int(val.split()[0])  # kB
        mtot = info.get('MemTotal', 0)
        mava = info.get('MemAvailable', info.get('MemFree', 0))
        if mtot > 0:
            mem_total_mb = mtot // 1024
            mem_used_mb = (mtot - mava) // 1024
            mem_pct = round(100.0 * (mtot - mava) / mtot, 1)
    except Exception:
        pass

    # --- Network throughput (all non-loopback interfaces) ---
    rx_bps = tx_bps = 0
    net_pct = None
    global _net_counters_prev
    try:
        rx = tx = 0
        for line in open('/proc/net/dev').read().splitlines()[2:]:
            name, data = line.split(':', 1)
            if name.strip() == 'lo':
                continue
            fields = data.split()
            if len(fields) >= 9:
                rx += int(fields[0])
                tx += int(fields[8])
        now = time.time()
        with _net_counters_lock:
            prev = _net_counters_prev
            dt = now - prev['t'] if prev['t'] else 0
            if dt > 0 and prev['t'] > 0:
                rx_bps = max(0, int((rx - prev['rx']) / dt))
                tx_bps = max(0, int((tx - prev['tx']) / dt))
                # utilisation vs assumed 100 Mbps link
                net_pct = min(100.0, round(100.0 * (rx_bps + tx_bps) * 8 / (100 * 1000 * 1000), 2))
            _net_counters_prev = {'rx': rx, 'tx': tx, 't': now}
    except Exception:
        pass

    # --- Disk (logs partition) ---
    disk_pct = None
    disk_used_gb = disk_total_gb = 0.0
    try:
        target = '/opt/pv-controller/logs' if os.path.isdir('/opt/pv-controller/logs') else '/'
        du = shutil.disk_usage(target)
        disk_total_gb = round(du.total / (1024 ** 3), 1)
        disk_used_gb = round((du.total - du.free) / (1024 ** 3), 1)
        disk_pct = round(100.0 * du.used / du.total, 1)
    except Exception:
        pass

    load1 = load5 = load15 = None
    try:
        load1, load5, load15 = [round(x, 2) for x in os.getloadavg()]
    except Exception:
        pass

    proc_rss_mb = proc_threads = None
    try:
        with open('/proc/self/status') as f:
            status_txt = f.read()
        m = re.search(r'^VmRSS:\s+(\d+)\s+kB', status_txt, re.M)
        if m:
            proc_rss_mb = round(int(m.group(1)) / 1024, 1)
        m = re.search(r'^Threads:\s+(\d+)', status_txt, re.M)
        if m:
            proc_threads = int(m.group(1))
    except Exception:
        pass

    return {
        'cpu': {'percent': cpu_pct},
        'memory': {'percent': mem_pct, 'used_mb': mem_used_mb, 'total_mb': mem_total_mb},
        'network': {
            'percent': net_pct,
            'rx_kbps': round(rx_bps / 1024, 1),
            'tx_kbps': round(tx_bps / 1024, 1),
        },
        'disk': {'percent': disk_pct, 'used_gb': disk_used_gb, 'total_gb': disk_total_gb},
        'load_avg': {'m1': load1, 'm5': load5, 'm15': load15},
        'process': {'rss_mb': proc_rss_mb, 'threads': proc_threads,
                    'uptime_s': int(time.time() - SERVER_STARTED_AT)},
    }


@app.route('/api/system/metrics')
def system_metrics():
    """Live host performance metrics for the HMI diagnostics panel."""
    return jsonify(_read_host_metrics())


@app.route('/api/system/info')
def system_info():
    """Live network/system topology info for the HMI diagnostics panel."""
    controller_ips = []
    try:
        host_ips = socket.gethostbyname_ex(socket.gethostname())[2]
        controller_ips = [ip for ip in host_ips if not ip.startswith('127.')]
    except Exception:
        pass

    mqtt_ok = bool(mqtt_client.is_connected()) if mqtt_client else False
    modbus_port = int(os.getenv('MODBUS_PORT', '15002'))
    modbus_listening = False
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(0.5)
        modbus_listening = probe.connect_ex(('127.0.0.1', modbus_port)) == 0
        probe.close()
    except Exception:
        pass

    return jsonify({
        'controller_ips': controller_ips,
        'mqtt_broker': {
            'host': MQTT_BROKER,
            'port': 1883,
            'websocket_port': 9001,
            'connected': mqtt_ok,
        },
        'modbus': {'port': modbus_port, 'listening': modbus_listening},
        'session': MQTT_SESSION_TOKEN,
        'firmware': 'PV-CTRL v2.4.1',
        'site': 'CY-LIM-042',
        'server_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    })


@app.route('/api/admin/devices', methods=['GET', 'POST'])
def admin_devices_compat():
    """Legacy devices endpoint compatibility for noise and XSS training flows."""
    conn = sqlite3.connect('challenge_admin.db')
    cur = conn.cursor()
    try:
        if request.method == 'GET':
            cur.execute('SELECT id, name, type, status, ip_address FROM devices ORDER BY id DESC LIMIT 200')
            rows = cur.fetchall()
            devices = [{
                'id': r[0],
                'name': r[1],
                'description': f"{r[2]} | {r[3]} | {r[4]}",
                'type': r[2],
                'status': r[3],
                'ip_address': r[4]
            } for r in rows]
            return jsonify({'devices': devices})

        data = request.json or {}
        name = data.get('name') or 'device'
        description = data.get('description') or ''
        try:
            write_action_log('admin_device_created', actor='dashboard_user', details={'name': name, 'description': description})
        except Exception:
            logger.exception('Failed to write action log for device creation')
        cur.execute(
            'INSERT INTO devices (name, type, status, ip_address) VALUES (?, ?, ?, ?)',
            (name, description[:64] or 'unknown', 'online', '172.20.0.99')
        )
        conn.commit()
        return jsonify({'result': 'ok'})
    finally:
        cur.close()
        conn.close()


@app.route('/admin/mqtt_data', methods=['GET'])
def admin_mqtt_data_compat():
    """Legacy admin mqtt data endpoint."""
    return jsonify(mqtt_series[-200:])


@app.route('/replayer/state', methods=['GET', 'POST'])
def replayer_state_compat():
    """Legacy replayer endpoint used by replayer sidecar."""
    if request.method == 'POST':
        replayer_state['last_played'] = time.time()
        return jsonify({'result': 'ok'})
    return jsonify({'running': replayer_state['running'], 'last_played': replayer_state['last_played']})


@app.route('/victim/log', methods=['POST'])
def victim_log_compat():
    """Legacy victim telemetry endpoint compatibility."""
    data = request.json or {}
    msg = data.get('msg') or data.get('message') or data.get('log')
    if not msg:
        return jsonify({'error': 'missing msg'}), 400
    try:
        with open('/opt/pv-controller/logs/victim.log', 'a') as fh:
            fh.write(f"{datetime.now().isoformat()} {msg}\n")
    except Exception:
        pass
    return jsonify({'result': 'ok'})


@app.route('/vite.svg')
def vite_svg_compat():
    """Silence missing favicon requests from Vite-built dashboard."""
    return ('', 204)

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
    
    if log_type == 'admin_dashboard_actions':
        log_file = ADMIN_UI_LOG_FILE
    else:
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

@app.route("/api/tickets", methods=["POST"])
def submit_ticket():
    """Public ticket submission for normal users (no account required)."""
    data = request.get_json(silent=True) or {}
    reporter = (data.get('reporter') or data.get('name') or '').strip()
    subject = (data.get('subject') or '').strip()
    description = (data.get('description') or '').strip()

    if not subject or not description:
        return jsonify({'error': 'Subject and description are required'}), 400
    if not reporter:
        reporter = 'anonymous'

    ticket = state.add_ticket(
        subject=subject,
        description=description,
        reporter=reporter,
        source='user',
        category=(data.get('category') or 'support'),
        ip=request.remote_addr,
    )
    try:
        write_action_log('ticket_submitted', actor=reporter,
                         details={'ticket_id': ticket['id'], 'subject': ticket['subject']})
    except Exception:
        pass
    return jsonify({'status': 'ok', 'ticket_id': ticket['id']}), 201


@app.route("/api/admin/tickets", methods=["GET"])
def admin_list_tickets():
    """All tickets (user submissions + auto-raised incidents) for the admin."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not validate_token(token):
        return jsonify({"error": "Invalid or expired token"}), 403
    with state.lock:
        tickets = list(reversed(state.tickets))
    return jsonify({
        'tickets': tickets,
        'open_count': sum(1 for t in tickets if t['status'] == 'open'),
    })


@app.route("/api/admin/tickets/<int:ticket_id>/status", methods=["POST"])
def admin_update_ticket(ticket_id):
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    token_data = validate_token(token)
    if not token_data:
        return jsonify({"error": "Invalid or expired token"}), 403
    data = request.get_json(silent=True) or {}
    status = (data.get('status') or '').strip()
    if status not in ('open', 'investigating', 'resolved', 'closed'):
        return jsonify({'error': 'Invalid status'}), 400
    ticket = state.update_ticket_status(ticket_id, status)
    if not ticket:
        return jsonify({'error': 'Ticket not found'}), 404
    try:
        write_action_log('ticket_status_changed',
                         actor=token_data.get('username', 'admin'),
                         details={'ticket_id': ticket_id, 'status': status})
    except Exception:
        pass
    return jsonify({'status': 'ok', 'ticket': ticket})


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
        state.notification_seq += 1
        notification = {
            'id': state.notification_seq,
            'timestamp': datetime.now().isoformat(),
            'type': 'urgent',
            'title': '⚠️ System Alert',
            'message': message,
            'link': phishing_url,
            'link_text': 'Verify Credentials',
            'read': False
        }
        state.notifications.append(notification)
        # Keep last 20 notifications (IDs stay unique thanks to the counter)
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
    try:
        write_action_log('notification_marked_read', actor='dashboard_user', details={'notification_id': notification_id})
    except Exception:
        logger.exception('Failed to write action log for notification read')
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
    try:
        write_action_log('security_events_cleared', actor=token_data.get('username', 'admin'), details={'cleared_events': count})
    except Exception:
        logger.exception('Failed to write action log for clear events')
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
    try:
        write_action_log('ip_blocked', actor=token_data.get('username', 'admin'), details={'ip': ip, 'reason': reason, 'revoked_sessions': revoked})
    except Exception:
        logger.exception('Failed to write action log for block ip')

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
    try:
        write_action_log('ip_unblocked', actor=token_data.get('username', 'admin'), details={'ip': ip})
    except Exception:
        logger.exception('Failed to write action log for unblock ip')
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
    try:
        write_action_log('ip_disconnected', actor=token_data.get('username', 'admin'), details={'ip': ip, 'revoked_sessions': revoked})
    except Exception:
        logger.exception('Failed to write action log for disconnect ip')
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
            title = event.get('title') or event.get('message') or 'Security Alert'
            try:
                ticket_path = write_ticket_text(
                    'acknowledgement_ticket',
                    title,
                    [
                        f"Analyst: {analyst}",
                        f"Event Timestamp: {event_timestamp}",
                        f"Severity: {event.get('severity', 'unknown')}",
                        f"Category: {event.get('category', 'unknown')}",
                        f"Source: {event.get('source', 'unknown')}",
                        f"IP: {event.get('ip', '')}",
                        "",
                        "Notes:",
                        notes or '(none)'
                    ]
                )
                write_action_log('alert_acknowledged', actor=analyst, details={'event_timestamp': event_timestamp, 'ticket_file': ticket_path})
            except Exception:
                logger.exception('Failed to write ticket/action logs for acknowledgement')
            
            logger.info(f"✅ Alert acknowledged by {analyst}: {title}")
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
    try:
        ticket_path = write_ticket_text(
            'security_ticket',
            title,
            [
                f"Submitted By: {token_data.get('username', 'admin')}",
                f"Severity: {severity}",
                f"Category: {category}",
                f"Source: {source}",
                f"IP: {ip or ''}",
                "",
                "Details:",
                details or '(none)'
            ]
        )
        write_action_log('security_ticket_submitted', actor=token_data.get('username', 'admin'), details={'title': title, 'severity': severity, 'ticket_file': ticket_path})
    except Exception:
        logger.exception('Failed to write ticket/action logs for created security event')
    
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
    ensure_documents_dirs()
    
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
