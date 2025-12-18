import json
import logging
import sqlite3
import os
import socket
import secrets
import hashlib
try:
    # pymodbus 3.x API
    from pymodbus.server import StartTcpServer
    from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
    from pymodbus.device import ModbusDeviceIdentification
    HAS_PYMODBUS = True
except Exception:
    HAS_PYMODBUS = False
import threading
from queue import Queue
import time
from flask import Flask, jsonify, request, abort
try:
    import paho.mqtt.client as mqtt
    HAS_PAHO = True
except Exception:
    HAS_PAHO = False

logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
app.sse_clients = []
app.sse_lock = threading.Lock()
app.static_folder = 'static'

# Flags used by the challenge
FLAG_RECON = "BSY{PV_RECON_9a7c9f3f9f}"
FLAG_INJECTION = "BSY{PV_INJECTION_135b2aee7c}"
FLAG_HALT = "BSY{PV_HALT_4b7d0b6a8c}"
FLAG_MQTT_HIJACK = "BSY{PV_MQTT_HIJACK_7c8f1a}"
FLAG_REST_HIJACK = "BSY{PV_REST_HIJACK_22cd3b9d}"
FLAG_ADMIN_PANEL = "BSY{PV_DASH_7e3a56}"

# PV status
pv_status = {
    "status": "RUNNING",
    "last_update": time.time(),
    "power": 3200
}

# Replayer control state
replayer_state = {'running': False, 'last_played': None}

# Event timeline enforcement for this challenge: ensure E1 (recon) occurs before E2/E3
events_done = {
    'recon': False
}
stolen_credentials = []
events_extra = {
    'arp_spoofed': False,
    'phished': False,
    'session_stolen': False,
}

# Credentials (weak by design for training purposes)
# WARNING: In production IoT systems, use WPA3, strong passwords (20+ chars), and certificate-based auth
WIFI_SSID = "HomeWiFi_PV"
WIFI_PASSWORD = "super-secret-123"  # Vulnerable: weak password, dictionary attack susceptible

# REST API token (set after login)
api_tokens = set()
admin_tokens = set()
failed_login_attempts = {}
LOGIN_LOCKOUT_THRESHOLD = 3
LOGIN_LOCKOUT_DURATION = 60  # seconds
WEAK_PASSWORDS = ["123456", "password", "super-secret-123", "qwerty", "admin"]


def set_halt(by="unknown"):
    global pv_status
    pv_status["status"] = "HALTED"
    pv_status["halt_by"] = by
    pv_status["power"] = 0
    pv_status["last_update"] = time.time()
    logging.info(f"PV HALT by {by}")


@app.route("/")
def index():
    return jsonify({
        "service": "smart-home-pv-controller",
        "status": pv_status["status"],
        "note": "This is a simulated PV hub for training purposes"
    })


@app.route("/wifi_scan")
def wifi_scan():
    # Return easily discoverable credentials for the lab
    # mark event 'recon' as performed - this is a minimal check for storyline order
    events_done['recon'] = True
    # add a small arp_scan example to logs
    try:
        with open('logs/arp_scan.log', 'a') as fh:
            fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} RECON: wifi scan\n")
    except Exception:
        pass
    return jsonify({
        "ssid": WIFI_SSID,
        "password": WIFI_PASSWORD,
        "note": "Weak settings, for demo only",
        "flag": FLAG_RECON
    })


@app.route("/status")
def status():
    out = pv_status.copy()
    out['mqtt_session'] = globals().get('MQTT_SESSION_TOKEN', '')
    return jsonify(out)


@app.route("/flag")
def flag():
    # Only expose the final flag when PV is halted
    if pv_status["status"] == "HALTED":
        return jsonify({"flag": FLAG_HALT})
    else:
        abort(403)


@app.route('/flag/modbus', methods=['GET'])
def flag_modbus():
    if pv_status.get('halt_by') == 'MODBUS':
        return jsonify({"flag": FLAG_INJECTION})
    abort(403)


@app.route('/flag/mqtt', methods=['GET'])
def flag_mqtt():
    if pv_status.get('halt_by') == 'MQTT':
        return jsonify({"flag": FLAG_MQTT_HIJACK})
    abort(403)


@app.route('/flag/rest', methods=['GET'])
def flag_rest():
    if pv_status.get('halt_by') == 'REST':
        return jsonify({"flag": FLAG_REST_HIJACK})
    abort(403)


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")
    # Simple lockout logic per IP
    ip = request.remote_addr or "unknown"
    now = time.time()
    failed = failed_login_attempts.get(ip, {'count': 0, 'until': 0})
    if failed['until'] > now:
        return jsonify({"error": "locked", "until": failed['until']}), 403

    # For the challenge, the wifi password acts as admin password (weak link)
    # VULNERABILITY: Password reuse across WiFi and admin panel (CWE-255)
    if username == "admin" and password == WIFI_PASSWORD:
        # Generate more realistic session token (still predictable for training purposes)
        token = secrets.token_urlsafe(32)  # 256-bit token
        api_tokens.add(token)
        # SECURITY NOTE: In production, use JWT with expiration, refresh tokens, and secure storage
        return jsonify({"token": token})
    else:
        # register failed attempt
        failed['count'] = failed.get('count', 0) + 1
        if failed['count'] >= LOGIN_LOCKOUT_THRESHOLD:
            failed['until'] = now + LOGIN_LOCKOUT_DURATION
            failed['count'] = 0
        failed_login_attempts[ip] = failed
        # Show weak password hints if the password is in known weak list
        response = {"error": "unauthorized"}
        if password in WEAK_PASSWORDS:
            response['hint'] = 'weak_password_detected'
        return jsonify(response), 401


@app.route('/api/admin/login', methods=['POST'])
def admin_login():
        # intentionally vulnerable SQL-based login for the challenge
        data = request.json or {}
        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            return jsonify({'error': 'missing creds'}), 400
        try:
            conn = sqlite3.connect('challenge_admin.db')
            cur = conn.cursor()
            # VULNERABLE: string interpolation into SQL (SQL injection demo)
            q = "SELECT id, username FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
            cur.execute(q)
            r = cur.fetchone()
            if r:
                token = f"admintoken-{int(time.time())}"
                admin_tokens.add(token)
                try:
                    with open('logs/admin_login.log','a') as fh:
                        fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} LOGIN_SUCCESS {username}\n")
                except Exception:
                    pass
                return jsonify({'token': token})
            return jsonify({'error': 'unauthorized'}), 401
        except Exception as e:
            logging.exception('admin login failed')
            try:
                with open('logs/admin_login.log','a') as fh:
                    fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} LOGIN_FAILED {username}\n")
            except Exception:
                pass
            return jsonify({'error': 'server error'}), 500
        finally:
            try:
                cur.close()
                conn.close()
            except Exception:
                pass


@app.route('/api/admin/devices', methods=['GET', 'POST'])
def admin_devices():
        # No auth required for GET (public telemetry) to make it easier to learn attack patterns
        if request.method == 'GET':
            conn = sqlite3.connect('challenge_admin.db')
            cur = conn.cursor()
            try:
                cur.execute('SELECT id, name, description FROM devices')
                rows = cur.fetchall()
                devices = [{'id': r[0], 'name': r[1], 'description': r[2]} for r in rows]
                # intentionally do NOT escape device name to demonstrate stored XSS via dashboard
                return jsonify({'devices': devices})
            finally:
                cur.close()
                conn.close()

        # POST: create a new device; no content sanitization -> stored XSS
        if request.method == 'POST':
            data = request.json or {}
            name = data.get('name') or 'device'
            description = data.get('description') or ''
            conn = sqlite3.connect('challenge_admin.db')
            cur = conn.cursor()
            try:
                # VULNERABLE: naive insert; stored XSS via name
                cur.execute("INSERT INTO devices(name, description) VALUES('%s', '%s')" % (name, description))
                conn.commit()
                try:
                    with open('logs/admin_actions.log','a') as fh:
                        fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} ADD_DEVICE {name}\n")
                except Exception:
                    pass
                return jsonify({'result': 'ok'})
            finally:
                cur.close()
                conn.close()



@app.route('/api/login/lockouts', methods=['GET'])
def api_login_lockouts():
    # Expose a simple view of login lockouts and recent failing stats for training purposes
    now = time.time()
    data = {k: v for k, v in failed_login_attempts.items()}
    return jsonify({"lockouts": data, "now": now})


@app.route('/admin', methods=['GET'])
def admin_page():
    # Serve the admin dashboard UI; the dashboard will fetch devices and telemetry via /api/admin/* endpoints
    return app.send_static_file('dashboard.html')


@app.route('/admin/mqtt_data', methods=['GET'])
def admin_mqtt_data():
    # Return last N mqtt status points for plotting
    points = globals().get('mqtt_series', [])[-200:]
    return jsonify(points)


@app.route('/phish', methods=['POST'])
def phish():
    """Simulate a phishing landing page where credentials are gathered by the attacker.
    This is a simplified simulation where a POST with username/password stores the cred and sets events.
    """
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    if username and password:
        stolen_credentials.append({'username': username, 'password': password, 'when': time.time()})
        events_extra['phished'] = True
        try:
            with open('logs/phish.log','a') as fh:
                fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} STOLE: {username}:{password}\n")
        except Exception:
            pass
        return jsonify({"result": "ok", "message": "Thanks, login accepted"})
    return jsonify({"error": "missing username or password"}), 400


@app.route('/do_arp_spoof', methods=['POST'])
def do_arp_spoof():
    # Simulate ARP spoofing; on the real network this would allow an attacker to intercept traffic
    events_extra['arp_spoofed'] = True
    # add to arp log
    try:
        with open('logs/arp_scan.log', 'a') as fh:
            fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} ARP_SPOOF: attacker started\n")
    except Exception:
        pass
    return jsonify({"result": "ok"})


@app.route('/phish_page', methods=['GET'])
def phish_page():
    return app.send_static_file('phish_page.html')


@app.route('/phish_email', methods=['GET'])
def phish_email():
    return app.send_static_file('phish_email.html')


@app.route('/walkthrough', methods=['GET'])
def walkthrough_page():
    return app.send_static_file('walkthrough.html')


@app.route('/modbus_inject', methods=['POST'])
def modbus_inject():
    # For testing: write coil 1 (trigger modbus) via low-level execution
    if not events_done.get('recon', False):
        return jsonify({'error':'recon_required'}), 403
    # raw TCP fallback for modbus-like injection
    try:
        s = socket.socket()
        s.connect(('127.0.0.1', 15002))
        s.sendall(b'WRITE HALT\n')
        s.close()
    except Exception as e:
        return jsonify({'error':str(e)}), 500
    return jsonify({'result':'ok'})


@app.route('/sim_mqtt', methods=['POST'])
def sim_mqtt():
    # Simulate attacker publishing HALT with session token
    data = request.json or {}
    session = data.get('session')
    if not session:
        return jsonify({'error':'no session provided'}), 400
    # If paho available, publish; otherwise store session and call the internal handler directly
    try:
        if HAS_PAHO:
            client = mqtt.Client()
            client.connect('mosquitto',1883,60)
            client.publish('pv/control', json.dumps({'command':'HALT','session':session}))
            client.disconnect()
        else:
            # emulate the message by directly calling on_message handler (not recommended) — or set state
            events_extra['session_stolen'] = True
    except Exception as e:
        return jsonify({'error':str(e)}), 500
    return jsonify({'result':'ok'})


@app.route('/capture_hash', methods=['GET'])
def capture_hash():
    # Return a SHA-256 digest of the admin password to simulate captured hash
    import hashlib
    h = hashlib.sha256()
    h.update(WIFI_PASSWORD.encode())
    hexh = h.hexdigest()
    try:
        with open('logs/hash_capture.log','a') as fh:
            fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} HASH:{hexh}\n")
    except Exception:
        pass
    return jsonify({'hash': hexh})


@app.route('/logs/<path:filename>', methods=['GET'])
def logs_serve(filename):
    # Basic log retrieval for training (read-only) — only allow files from logs/ directory
    safe_path = os.path.join('logs', os.path.basename(filename))
    if not os.path.exists(safe_path):
        abort(404)
    with open(safe_path,'rb') as fh:
        return fh.read()


@app.route('/attacker/creds', methods=['GET'])
def attacker_creds():
    # Only expose creds if they were phished/arpspofed
    if not events_extra['phished'] and not events_extra['arp_spoofed']:
        return jsonify({"error": "no creds captured"}), 403
    return jsonify({"creds": stolen_credentials})


@app.route('/attacker/session', methods=['GET'])
def attacker_session():
    # If attacker ARP-spoofed, they can read the session token from the status 'pv/status' traffic
    if not events_extra['arp_spoofed']:
        return jsonify({"error": "no session captured"}), 403
    # return the token (if present). Mark session as stolen for path enforcement
    token = globals().get('MQTT_SESSION_TOKEN', '')
    if token:
        events_extra['session_stolen'] = True
    return jsonify({"session": token})


@app.route('/victim/log', methods=['POST'])
def victim_log():
    data = request.json or {}
    msg = data.get('msg') or data.get('message') or data.get('log')
    if not msg:
        return jsonify({'error': 'missing msg'}), 400
    try:
        with open('logs/victim.log','a') as fh:
            fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
    except Exception:
        pass
    if 'XSS' in msg.upper():
        events_extra['xss_detected'] = True
    return jsonify({'result': 'ok'})


@app.route('/victim/status', methods=['GET'])
def victim_status():
    st = {'xss_detected': events_extra.get('xss_detected', False)}
    try:
        with open('logs/victim.log','r') as fh:
            lines = fh.readlines()[-20:]
            st['recent'] = [l.strip() for l in lines]
    except Exception:
        st['recent'] = []
    return jsonify(st)


@app.route('/replayer/start', methods=['POST'])
def replayer_start():
    replayer_state['running'] = True
    replayer_state['last_played'] = time.time()
    try:
        with open('logs/replayer.log','a') as fh:
            fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} REPLAYER START\n")
    except Exception:
        pass
    return jsonify({'result': 'ok'})


@app.route('/replayer/stop', methods=['POST'])
def replayer_stop():
    replayer_state['running'] = False
    try:
        with open('logs/replayer.log','a') as fh:
            fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} REPLAYER STOP\n")
    except Exception:
        pass
    return jsonify({'result': 'ok'})


@app.route('/replayer/state', methods=['GET'])
def replayer_state_get():
    return jsonify({'running': replayer_state['running'], 'last_played': replayer_state['last_played']})


@app.route("/api/hub/command", methods=["POST"])
def hub_command():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "no auth"}), 401
    token = auth.split(" ", 1)[1]
    if token not in api_tokens:
        return jsonify({"error": "invalid token"}), 403

    cmd = (request.json or {}).get("command")
    if not cmd:
        return jsonify({"error": "no command"}), 400
    if cmd.upper() in ["HALT", "STOP"]:
        # REST API call requires credentials to be stolen via phishing
        if not events_extra.get('phished', False):
            return jsonify({"error": "credentials_required"}), 403
        set_halt(by="REST")
        return jsonify({"result": "ok", "flag": FLAG_REST_HIJACK})
    return jsonify({"error": "unknown command"}), 400


@app.route('/api/hub/restart', methods=['POST'])
def hub_restart():
    # Bring the PV back online and set power to default value
    pv_status['status'] = 'RUNNING'
    pv_status['power'] = 3000
    pv_status['last_update'] = time.time()
    try:
        with open('logs/admin_actions.log','a') as fh:
            fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} RESTART\n")
    except Exception:
        pass
    return jsonify({'result': 'ok'})


def tcp_command_listener(host="0.0.0.0", port=15002):
    # Minimalistic TCP server that simulates a Modbus-like interface
    # Keep the old behaviour for backward compatibility - but we'll also provide a proper Modbus server
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((host, port))
        srv.listen(5)
        logging.info(f"TCP Modbus-like server listening on {host}:{port}")
    except Exception as e:
        logging.info(f"Could not bind raw TCP listener on {host}:{port}: {e}")
        return

    def raw_tcp_loop():
        while True:
            conn, addr = srv.accept()
            logging.info(f"TCP connection from {addr}")
            try:
                data = conn.recv(1024).decode(errors="ignore").strip()
                logging.info(f"TCP received: {data}")
                if "HALT" in data.upper() or "WRITE HALT" in data.upper():
                    # enforce that recon was performed first
                    if not events_done.get('recon', False):
                        logging.info(f"TCP HALT rejected - recon not performed: {addr}")
                        conn.sendall(b"ERR:RECON_REQUIRED\n")
                    else:
                        set_halt(by='MODBUS')
                        conn.sendall(b"OK HALTED\n")
                else:
                    conn.sendall(b"ERR\n")
            finally:
                conn.close()

    threading.Thread(target=raw_tcp_loop, daemon=True).start()


def pymodbus_server(host="0.0.0.0", port=15002):
    # Modbus server that exposes a coil (0) which when set to 1 triggers a HALT
    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0]*100),
        co=ModbusSequentialDataBlock(0, [0]*100),
        hr=ModbusSequentialDataBlock(0, [0]*100),
        ir=ModbusSequentialDataBlock(0, [0]*100)
    )
    context = ModbusServerContext(slaves=store, single=True)

    identity = ModbusDeviceIdentification()
    identity.VendorName = 'StratoCyberLab'
    identity.ProductCode = 'PV'
    identity.VendorUrl = 'https://stratocyberlab'
    identity.ProductName = 'PV Inverter'
    identity.ModelName = 'PV_INVERTER' 

    # Start a monitor thread to detect changes in coil 1
    def monitor_coil():
        last_val = 0
        while True:
            rr = context[0].getValues(1, 1, count=1)
            val = rr[0] if rr else 0
            if val == 1 and last_val == 0:
                if not events_done.get('recon', False):
                    logging.info("Modbus HALT ignored - recon not performed yet")
                else:
                    logging.info("Modbus coil 1 set - triggering HALT")
                    set_halt(by='MODBUS')
            last_val = val
            time.sleep(0.5)

    t = threading.Thread(target=monitor_coil, daemon=True)
    t.start()

    try:
        StartTcpServer(context, identity=identity, address=(host, port))
    except Exception as e:
        logging.exception("Failed to start pymodbus server: %s", e)


def mqtt_client_loop(broker_host="mosquitto", broker_port=1883):
    client = mqtt.Client(client_id="pv-sim")
    global MQTT_SESSION_TOKEN, mqtt_series
    MQTT_SESSION_TOKEN = f"mqtt-session-{int(time.time())}"
    if 'mqtt_series' not in globals():
        mqtt_series = []

    def on_connect(client, userdata, flags, rc):
        logging.info("MQTT connected, subscribing to pv/control")
        client.subscribe("pv/control")
        client.subscribe("pv/telemetry")
        # Publish initial status including session token
        client.publish("pv/status", json.dumps({"status": pv_status["status"], "session": MQTT_SESSION_TOKEN, "power": pv_status.get('power', 0) }))

    def on_message(client, userdata, msg):
        payload = msg.payload.decode(errors="ignore")
        try:
            with open('logs/mqtt_traffic.log','a') as fh:
                fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} MQTT {msg.topic} {payload}\n")
        except Exception:
            pass
        logging.info(f"MQTT message on {msg.topic}: {payload}")
        # Accept payload as either simple 'HALT' or a JSON like {"command":"HALT","session":"..."}
        command = None
        token = None
        numeric_value = None
        try:
            payloadj = json.loads(payload)
            command = payloadj.get('command')
            token = payloadj.get('session')
        except Exception:
            command = payload

        if msg.topic == 'pv/telemetry':
            # telemetry message from sensors: add to series
            try:
                payloadj = json.loads(payload)
                # choose 'power' or 'value' in telemetry payload
                numeric_value = payloadj.get('power') or payloadj.get('value')
                if numeric_value is not None:
                        # mqtt_series already declared at the top of the function
                    mqtt_series.append({'ts': time.time(), 'value': numeric_value, 'power': numeric_value})
                    # broadcast the new telemetry point to SSE clients
                    payload = { 'ts': time.time(), 'value': numeric_value, 'power': numeric_value, 'topic': msg.topic }
                    try:
                        with app.sse_lock:
                            for q in list(app.sse_clients):
                                try:
                                    q.put_nowait(payload)
                                except Exception:
                                    pass
                    except Exception:
                        pass
            except Exception:
                pass
            return

        if command and isinstance(command, str) and command.upper() in ["HALT", "STOP"]:
            # Do not allow commands unless recon performed and ARP spoofing was done
            if not events_done.get('recon', False):
                logging.info("MQTT HALT rejected - recon not performed")
                return
            if not events_extra.get('arp_spoofed', False) and not events_extra.get('session_stolen', False):
                logging.info("MQTT HALT rejected - session not captured (ARP spoof missing)")
                return
            # allow command if session token matches OR if no token provided (to demonstrate unsecured channel)
            if not token or token == MQTT_SESSION_TOKEN:
                logging.info("MQTT HALT command accepted")
                set_halt(by="MQTT")
                # store state for admin graphs
                # mqtt_series already declared at the top of the function
                mqtt_series.append({ 'ts': time.time(), 'value': pv_status.get('power', 0), 'power': pv_status.get('power', 0) })
                # Also broadcast the pv/status point for SSE clients
                payload = { 'ts': time.time(), 'value': pv_status.get('power', 0), 'power': pv_status.get('power', 0), 'topic': 'pv/status' }
                try:
                    with app.sse_lock:
                        for q in list(app.sse_clients):
                            try:
                                q.put_nowait(payload)
                            except Exception:
                                pass
                except Exception:
                    pass
            else:
                logging.info("MQTT HALT command rejected due to session mismatch")

    client.on_connect = on_connect
    client.on_message = on_message
    try:
        client.connect(broker_host, broker_port, 60)
    except Exception as e:
        logging.warning(f"MQTT connection failed: {e}")
        return
    # publish periodic status updates every 5s so that a hijacker can steal session token
    def publisher_loop():
        while True:
            # publish periodic status including numeric power value
            # Simulate realistic power fluctuations when running
            try:
                if pv_status.get('status') == 'RUNNING':
                    import random
                    base = pv_status.get('power', 3200)
                    # small realistic drift
                    delta = random.randint(-50, 50)
                    newp = max(0, min(5000, base + delta))
                    pv_status['power'] = newp
            except Exception:
                pass
            client.publish("pv/status", json.dumps({"status": pv_status["status"], "session": MQTT_SESSION_TOKEN, "power": pv_status.get('power', 0)}))
            # update graph data
            try:
                # mqtt_series already declared at the top of the function
                mqtt_series.append({'ts': time.time(), 'value': pv_status.get('power', 0), 'power': pv_status.get('power', 0)})
                # keep last 500 points
                if len(mqtt_series) > 1000:
                    mqtt_series = mqtt_series[-1000:]
            except Exception:
                pass
            time.sleep(5)

    publisher = threading.Thread(target=publisher_loop, daemon=True)
    publisher.start()

    client.loop_forever()


def start_tcpdump_if_available():
    import shutil, subprocess
    try:
        if shutil.which('tcpdump'):
            # ensure logs directory
            os.makedirs('logs', exist_ok=True)
            p = subprocess.Popen(['tcpdump','-i','any','-w','logs/traffic.pcap','-U'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logging.info('tcpdump started with pid %s' % p.pid)
    except Exception as e:
        logging.info('tcpdump start failed: %s' % e)


def init_db():
    try:
        conn = sqlite3.connect('challenge_admin.db')
        cur = conn.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS devices (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, description TEXT)''')
        # seed admin user
        try:
            cur.execute("INSERT INTO users(username,password) VALUES(?,?)", ('admin', WIFI_PASSWORD))
        except sqlite3.IntegrityError:
            pass
        # seed some devices
        cur.execute("SELECT COUNT(*) FROM devices")
        if cur.fetchone()[0] == 0:
            cur.execute("INSERT INTO devices(name,description) VALUES(?,?)", ('PV-Inverter-01','Main inverter'))
            cur.execute("INSERT INTO devices(name,description) VALUES(?,?)", ('Battery-01','Battery bank'))
        conn.commit()
    except Exception:
        logging.exception('failed to init admin db')
    finally:
        try:
            cur.close()
            conn.close()
        except Exception:
            pass


@app.route('/admin/mqtt_stream', methods=['GET'])
def admin_mqtt_stream():
    # SSE endpoint that streams mqtt telemetry points to dashboard clients
    def event_stream(q: Queue):
        try:
            # send a one-line comment to initiate stream
            yield ": connected\n\n"
            while True:
                data = q.get()
                # SSE format: data: <payload>\n\n
                yield f"data: {json.dumps(data)}\n\n"
        except GeneratorExit:
            # Client disconnected
            return

    q = Queue()
    with app.sse_lock:
        app.sse_clients.append(q)
        logging.info('SSE client registered, total=%d' % len(app.sse_clients))
    # return the stream, and make sure to remove queue on disconnect
    def generator():
        try:
            for chunk in event_stream(q):
                yield chunk
        finally:
            with app.sse_lock:
                try:
                    app.sse_clients.remove(q)
                except ValueError:
                    pass
            logging.info('SSE client disconnected, total=%d' % len(app.sse_clients))

    return app.response_class(generator(), mimetype='text/event-stream')


@app.route('/sse/mqtt_stream', methods=['GET'])
def sse_mqtt_stream():
    # alias for external clients that may be routed differently
    return admin_mqtt_stream()


@app.route('/admin/publish_telemetry', methods=['POST'])
def admin_publish_telemetry():
    # Accept a small JSON to publish on pv/telemetry; useful for testing live charts
    data = request.json or {}
    if not HAS_PAHO:
        return jsonify({'error': 'mqtt not available on server'}), 500
    try:
        pub = mqtt.Client()
        pub.connect(os.environ.get('MQTT_HOST', 'mosquitto'), 1883, 60)
        pub.publish('pv/telemetry', json.dumps(data))
        pub.disconnect()
        return jsonify({'result': 'ok'})
    except Exception as e:
        logging.exception('publish telemetry failed')
        return jsonify({'error': str(e)}), 500


def start_tcpdump_if_available():
    import shutil, subprocess
    try:
        if shutil.which('tcpdump'):
            # ensure logs directory
            os.makedirs('logs', exist_ok=True)
            p = subprocess.Popen(['tcpdump','-i','any','-w','logs/traffic.pcap','-U'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logging.info('tcpdump started with pid %s' % p.pid)
    except Exception as e:
        logging.info('tcpdump start failed: %s' % e)


def init_db():
    try:
        conn = sqlite3.connect('challenge_admin.db')
        cur = conn.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS devices (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, description TEXT)''')
        # seed admin user
        try:
            cur.execute("INSERT INTO users(username,password) VALUES(?,?)", ('admin', WIFI_PASSWORD))
        except sqlite3.IntegrityError:
            pass
        # seed some devices
        cur.execute("SELECT COUNT(*) FROM devices")
        if cur.fetchone()[0] == 0:
            cur.execute("INSERT INTO devices(name,description) VALUES(?,?)", ('PV-Inverter-01','Main inverter'))
            cur.execute("INSERT INTO devices(name,description) VALUES(?,?)", ('Battery-01','Battery bank'))
        conn.commit()
    except Exception:
        logging.exception('failed to init admin db')
    finally:
        try:
            cur.close()
            conn.close()
        except Exception:
            pass

if __name__ == "__main__":
    logging.info('server __main__ starting')
    # Start TCP server thread
    t = threading.Thread(target=tcp_command_listener, args=("0.0.0.0", 15002), daemon=True)
    t.start()
    # Start pymodbus server thread (only if installed)
    if HAS_PYMODBUS:
        p = threading.Thread(target=pymodbus_server, args=("0.0.0.0", 15002), daemon=True)
        p.start()
    # Start MQTT client thread (only if paho installed)
    if HAS_PAHO:
        m = threading.Thread(target=mqtt_client_loop, args=(os.environ.get("MQTT_HOST", "mosquitto"), 1883), daemon=True)
        m.start()

    # start tcpdump if installed
    try:
        threading.Thread(target=start_tcpdump_if_available, daemon=True).start()
    except Exception:
        pass
    # ensure logs folder exists for all log writes
    try:
        os.makedirs('logs', exist_ok=True)
    except Exception:
        pass
    init_db()
    logging.info('starting flask app')
    # Start web server (Flask). Set use_reloader=False to avoid parent process exiting
    app.run(host="0.0.0.0", port=80, debug=False, use_reloader=False)


@app.route('/admin/mqtt_stream', methods=['GET'])
def admin_mqtt_stream():
    # SSE endpoint that streams mqtt telemetry points to dashboard clients
    def event_stream(q: Queue):
        try:
            while True:
                data = q.get()
                # SSE format: data: <payload>\n\n
                yield f"data: {json.dumps(data)}\n\n"
        except GeneratorExit:
            # Client disconnected
            return

    q = Queue()
    with app.sse_lock:
        app.sse_clients.append(q)
        logging.info('SSE client registered, total=%d' % len(app.sse_clients))
    # return the stream, and make sure to remove queue on disconnect
    def generator():
        try:
            for chunk in event_stream(q):
                yield chunk
        finally:
            with app.sse_lock:
                try:
                    app.sse_clients.remove(q)
                except ValueError:
                    pass
            logging.info('SSE client disconnected, total=%d' % len(app.sse_clients))

    return app.response_class(generator(), mimetype='text/event-stream')


@app.route('/sse/mqtt_stream', methods=['GET'])
def sse_mqtt_stream():
    # alias for external clients that may be routed differently
    return admin_mqtt_stream()


@app.route('/admin/publish_telemetry', methods=['POST'])
def admin_publish_telemetry():
    # Accept a small JSON to publish on pv/telemetry; useful for testing live charts
    data = request.json or {}
    if not HAS_PAHO:
        return jsonify({'error': 'mqtt not available on server'}), 500
    try:
        pub = mqtt.Client()
        pub.connect(os.environ.get('MQTT_HOST', 'mosquitto'), 1883, 60)
        pub.publish('pv/telemetry', json.dumps(data))
        pub.disconnect()
        return jsonify({'result': 'ok'})
    except Exception as e:
        logging.exception('publish telemetry failed')
        return jsonify({'error': str(e)}), 500
    return jsonify({'result': 'ok'})

def start_tcpdump_if_available():
    import shutil, subprocess
    try:
        if shutil.which('tcpdump'):
            # ensure logs directory
            os.makedirs('logs', exist_ok=True)
            p = subprocess.Popen(['tcpdump','-i','any','-w','logs/traffic.pcap','-U'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logging.info('tcpdump started with pid %s' % p.pid)
    except Exception as e:
        logging.info('tcpdump start failed: %s' % e)


def init_db():
    try:
        conn = sqlite3.connect('challenge_admin.db')
        cur = conn.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS devices (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, description TEXT)''')
        # seed admin user
        try:
            cur.execute("INSERT INTO users(username,password) VALUES(?,?)", ('admin', WIFI_PASSWORD))
        except sqlite3.IntegrityError:
            pass
        # seed some devices
        cur.execute("SELECT COUNT(*) FROM devices")
        if cur.fetchone()[0] == 0:
            cur.execute("INSERT INTO devices(name,description) VALUES(?,?)", ('PV-Inverter-01','Main inverter'))
            cur.execute("INSERT INTO devices(name,description) VALUES(?,?)", ('Battery-01','Battery bank'))
        conn.commit()
    except Exception:
        logging.exception('failed to init admin db')
    finally:
        try:
            cur.close()
            conn.close()
        except Exception:
            pass
