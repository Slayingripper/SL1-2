import math
import socket
import time
import os
import json
import random
import requests
import paho.mqtt.client as mqtt

MQTT_HOST = os.environ.get('MQTT_HOST', 'mosquitto')
PV_HOST = os.environ.get('PV_HOST', 'pv-controller')
# Base publish/poll interval in seconds (jitter is added per cycle)
LOOP_INTERVAL = max(2.0, float(os.environ.get('NOISE_INTERVAL', '5')))
# Only poll HTTP endpoints every Nth cycle to keep CPU/network usage low
HTTP_POLL_EVERY = max(1, int(os.environ.get('NOISE_HTTP_POLL_EVERY', '4')))
# Publish interval for a dedicated per-site feeder (--site <id>)
SITE_INTERVAL = max(2.0, float(os.environ.get('SITE_INTERVAL', '5')))
# The aggregate publisher in noise_loop() is superseded by the dedicated
# per-site feeder containers; it can be re-enabled with NOISE_PUBLISH_SITES=1.
PUBLISH_ALL_SITES = os.environ.get('NOISE_PUBLISH_SITES', '0') == '1'
# Containers start in parallel, so the broker is often not accepting
# connections yet. Retry the initial handshake instead of publishing into a
# dead client (paho's publish() does not raise when offline, it just drops the
# message with a non-zero rc).
MQTT_CONNECT_ATTEMPTS = max(1, int(os.environ.get('MQTT_CONNECT_ATTEMPTS', '30')))
MQTT_CONNECT_BACKOFF = max(0.5, float(os.environ.get('MQTT_CONNECT_BACKOFF', '2')))
# How often --seed-loop refreshes the retained site data (minutes).
SEED_REFRESH_MINUTES = max(1.0, float(os.environ.get('SEED_REFRESH_MINUTES', '15')))
# Successful CONNACKs so far. The seed loop watches this to re-seed the moment
# the broker comes back, instead of waiting out the refresh interval.
CONNECTS = 0
# MQTT brokers drop an existing session when another client connects with the
# same client id, so every role needs its own id (the broker enforces a 23-char
# limit, hence the short fixed ids rather than the container hostname).
CLIENT_ID = os.environ.get('NOISE_CLIENT_ID', '')

client = None

# --- Area map sites ------------------------------------------------------
# Per-site telemetry for the Area Map view. Published on pv/telemetry/<id>
# (and seed history on pv/history/<id>) — deliberately NOT on the bare
# pv/telemetry topic, which the controller subscribes to and monitors for
# anomalies. Retained so a freshly loaded dashboard hydrates instantly.
SUNRISE_H = 6.5
SUNSET_H = 19.5

SITES = [
    {'id': 'house-1', 'type': 'house', 'capacity_kw': 5.2, 'v_nom': 230.0, 'three_phase': False},
    {'id': 'house-2', 'type': 'house', 'capacity_kw': 3.8, 'v_nom': 230.0, 'three_phase': False},
    {'id': 'house-3', 'type': 'house', 'capacity_kw': 6.4, 'v_nom': 230.0, 'three_phase': False},
    {'id': 'pv-plant', 'type': 'plant', 'capacity_kw': 120.0, 'v_nom': 400.0, 'three_phase': True},
    {'id': 'army-base', 'type': 'consumer', 'base_load_kw': 14.0, 'peak_load_kw': 26.0,
     'v_nom': 400.0, 'three_phase': True},
]


def solar_elevation(hour):
    """0..1 daylight factor; mirrors the dashboard's expected-power model."""
    if hour <= SUNRISE_H or hour >= SUNSET_H:
        return 0.0
    return math.sin(math.pi * (hour - SUNRISE_H) / (SUNSET_H - SUNRISE_H)) ** 1.35


def site_sample(site, ts):
    lt = time.localtime(ts)
    hour = lt.tm_hour + lt.tm_min / 60.0
    daylight = solar_elevation(hour)
    payload = {'site': site['id'], 'ts': round(ts, 3)}
    if site['type'] == 'consumer':
        base, peak = site['base_load_kw'], site['peak_load_kw']
        load = (base + (peak - base) * (0.35 + 0.65 * daylight)) * random.uniform(0.9, 1.1)
        payload['load_kw'] = round(load, 3)
        payload['power_kw'] = -payload['load_kw']  # signed: consumption
        payload['status'] = 'ok'
    else:
        power = site['capacity_kw'] * daylight * random.uniform(0.86, 1.0) + random.uniform(0.0, 0.05)
        payload['power_kw'] = round(power, 3)
        payload['status'] = 'ok' if power > 0.05 else 'idle'
    voltage = site['v_nom'] * random.uniform(0.985, 1.015)
    divisor = (math.sqrt(3) * voltage) if site['three_phase'] else voltage
    payload['voltage_v'] = round(voltage, 1)
    payload['current_a'] = round(abs(payload['power_kw']) * 1000.0 / divisor, 2)
    return payload


def publish_sites(now=None):
    now = now if now is not None else time.time()
    failed = 0
    for site in SITES:
        if not publish_ok(f"pv/telemetry/{site['id']}",
                          json.dumps(site_sample(site, now)), retain=True):
            failed += 1
    if failed:
        print(f'{failed}/{len(SITES)} site publishes failed', flush=True)
    return failed == 0


def get_own_ip():
    """Best-effort container IP (as seen on the route towards the broker)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((MQTT_HOST, 1883))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return 'unknown'


def site_loop(site_id):
    """Dedicated feeder: one container feeds exactly one map site with power.

    Publishes pv/telemetry/<id> every SITE_INTERVAL seconds, tagging each
    payload with 'seeder' metadata (container, ip, topic, seq, uptime) so the
    dashboard can show where the feed comes from. On startup it also seeds a
    retained 60-minute history on pv/history/<id>.
    """
    site = next((s for s in SITES if s['id'] == site_id), None)
    if site is None:
        print('unknown site id:', site_id, '- known:', [s['id'] for s in SITES])
        raise SystemExit(2)
    started = time.time()
    info = {
        'container': socket.gethostname(),
        'ip': get_own_ip(),
        'pid': os.getpid(),
        'interval_s': SITE_INTERVAL,
        'topic': f'pv/telemetry/{site_id}',
        'started_ts': round(started, 3),
    }
    print(f"site feeder up: {site_id} ({info['container']} @ {info['ip']})", flush=True)

    # Seed retained history so the sparkline is full on first dashboard load
    points = [site_sample(site, started - (59 - i) * 60) for i in range(60)]
    history = {'site': site_id, 'points': points, 'seeder': info}
    publish_ok(f'pv/history/{site_id}', json.dumps(history), retain=True)
    seeded_after_connect = CONNECTS

    seq = 0
    while True:
        # paho's loop auto-reconnects after a drop; ensure_network_loop() also
        # covers a first handshake that never came up, and a dead loop thread.
        if not ensure_network_loop():
            time.sleep(MQTT_CONNECT_BACKOFF)
        elif CONNECTS != seeded_after_connect:
            # Came back from an outage: re-arm the retained history so a late
            # broker never leaves the site dark.
            publish_ok(f'pv/history/{site_id}', json.dumps(history), retain=True)
            seeded_after_connect = CONNECTS
            print('feeder reconnected - telemetry resumed', flush=True)
        seq += 1
        now = time.time()
        payload = site_sample(site, now)
        payload['seeder'] = dict(info, seq=seq, uptime_s=round(now - started, 1))
        publish_ok(f'pv/telemetry/{site_id}', json.dumps(payload), retain=True)
        time.sleep(SITE_INTERVAL + random.uniform(0, SITE_INTERVAL * 0.3))


def seed_site_history(count=60):
    """Retained per-site history so map sparklines are full on first load."""
    now = time.time()
    ok = True
    for site in SITES:
        points = [site_sample(site, now - (count - 1 - i) * 60) for i in range(count)]
        if not publish_ok(f"pv/history/{site['id']}",
                          json.dumps({'site': site['id'], 'points': points}), retain=True):
            ok = False
        time.sleep(0.05)
    return publish_sites(now) and ok


def make_client(client_id):
    """Create an MQTT client that works with paho-mqtt 1.x and 2.x."""
    client_id = CLIENT_ID or client_id
    try:
        c = mqtt.Client(client_id=client_id,
                        callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    except (AttributeError, TypeError):
        c = mqtt.Client(client_id=client_id)
    # Registered before connecting so the CONNACK handler is live from the
    # first handshake.
    c.on_connect = _on_connect
    c.on_disconnect = _on_disconnect
    return c


def _on_connect(_client, _userdata, _flags, reason_code, _properties=None):
    """Callback API v2 signature (v1 passes rc in the reason_code slot)."""
    global CONNECTS
    rc = getattr(reason_code, 'value', reason_code)
    try:
        rc = int(rc)
    except (TypeError, ValueError):
        rc = -1
    if rc == 0:
        CONNECTS += 1
        print(f'MQTT connected to {MQTT_HOST}', flush=True)
    else:
        print(f'MQTT connection refused (rc={rc})', flush=True)


def _on_disconnect(_client, _userdata, *args):
    """The network loop reconnects on its own; just make the gap visible."""
    print('MQTT disconnected - reconnecting in background', flush=True)


def _wait_connected(timeout=5.0):
    """Give the network loop a moment to register CONNACK."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if client.is_connected():
            return True
        time.sleep(0.1)
    return client.is_connected()


def connect_mqtt(attempts=None):
    """Connect to the broker, retrying with capped exponential backoff.

    Returns True once the broker accepted the connection and the network loop
    is running (paho then reconnects by itself if the link drops later)."""
    attempts = MQTT_CONNECT_ATTEMPTS if attempts is None else max(1, attempts)
    for attempt in range(1, attempts + 1):
        try:
            client.reconnect_delay_set(min_delay=1, max_delay=30)
            client.connect(MQTT_HOST, 1883, 60)
            client.loop_start()
            if _wait_connected():
                return True
            print(f'MQTT handshake did not complete (attempt {attempt}/{attempts})', flush=True)
            client.loop_stop()
        except Exception as e:
            print(f'MQTT connect attempt {attempt}/{attempts} failed: {e}', flush=True)
        # Exponential backoff, capped so a long outage still retries often.
        time.sleep(min(MQTT_CONNECT_BACKOFF * (2 ** (attempt - 1)), 30.0))
    return False


def ensure_network_loop():
    """Guarantee the paho network thread is running before we publish.

    paho's loop only auto-reconnects if it is still running; if it ever died
    (or never started because the first connect failed) the client would sit
    there silently accepting-and-dropping publishes forever. This brings it
    back if needed, and reports whether the client is genuinely usable."""
    if not client.is_connected():
        if not connect_mqtt(attempts=1):
            return False
    elif not getattr(client, '_thread', None):
        try:
            client.loop_start()
        except Exception as e:
            print(f'failed to restart network loop: {e}', flush=True)
            return False
    return client.is_connected()


def publish_ok(topic, payload, retain=False, qos=0):
    """Publish and verify paho accepted the message.

    Returns False (instead of silently dropping) when the client is offline so
    callers can surface the problem rather than pretending the seed worked."""
    try:
        info = client.publish(topic, payload, qos=qos, retain=retain)
    except Exception as e:
        print(f'publish error on {topic}: {e}', flush=True)
        return False
    rc = getattr(info, 'rc', 0)
    if rc != 0:
        print(f'publish dropped on {topic}: rc={rc}', flush=True)
        return False
    return True


def seed_telemetry(count=60):
    """Send a burst of realistic daytime PV telemetry to fill the chart on startup."""
    base = time.time() - count * 60
    for i in range(count):
        # Bell-ish solar production curve scaled to a residential system (kW)
        phase = i / max(1, count - 1)
        curve = max(0.12, pow(phase, 0.6) * pow(1.0 - phase, 0.25))
        power_kw = round(random.uniform(2.8, 4.6) * curve + 0.15, 3)
        payload = {'ts': base + i * 60, 'power_kw': power_kw}
        if not publish_ok('pv/telemetry', json.dumps(payload)):
            return False
        time.sleep(0.05)
    return True


def seed_loop():
    """Seed once, then refresh the retained site data on an interval.

    The dashboard hydrates from the retained pv/telemetry/+ and pv/history/+
    messages. They are held in the broker's store, so anything that resets it
    (broker restart with persistence off, wiped volume, a feeder that was down
    while the broker bounced) leaves that site's sparkline empty until
    something republishes. Staying alive and re-seeding keeps the Area Map and
    the per-asset views populated for good."""
    interval = max(60.0, SEED_REFRESH_MINUTES * 60.0)
    print(f'seeder loop up: seed now, refresh every {interval / 60:.0f} min', flush=True)
    seeded_after_connect = -1
    while True:
        # Nothing in here may terminate the process: the whole point of this
        # loop is that it outlives transient broker/publish failures.
        try:
            if not ensure_network_loop():
                # The refresh loop never exits on a broker outage - it keeps
                # trying and re-seeds as soon as the broker is back.
                time.sleep(MQTT_CONNECT_BACKOFF)
                continue
            # Re-seed on a fresh connection as well as on the timer: a broker
            # restart (even a persistent one) can leave retained data missing
            # or stale, and the dashboard is watching.
            if CONNECTS != seeded_after_connect:
                if seeded_after_connect != -1:
                    # Only the retained data is worth re-sending on a
                    # reconnect; the pv/telemetry burst has been consumed.
                    print('broker reconnected - re-seeding retained data', flush=True)
                    seed_site_history(count=60)
                else:
                    seed_telemetry(count=120)
                    seed_site_history(count=60)
                    print('seeded telemetry', flush=True)
                seeded_after_connect = CONNECTS
            # Sleep in short slices so a reconnect is noticed promptly.
            deadline = time.time() + interval
            while time.time() < deadline and CONNECTS == seeded_after_connect:
                time.sleep(min(2.0, max(0.0, deadline - time.time())))
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f'seed loop error (retrying): {e}', flush=True)
            time.sleep(MQTT_CONNECT_BACKOFF)


def noise_loop():
    cycle = 0
    while True:
        try:
            ensure_network_loop()
            # MQTT: publish background sensor noise
            payload = {'ts': time.time(), 'value': random.randint(0, 100)}
            publish_ok('pv/telemetry', json.dumps(payload))

            # Aggregate per-site feed — off by default now that each map site
            # has its own dedicated feeder container (see docker-compose.yml)
            if PUBLISH_ALL_SITES:
                publish_sites()

            # Poll HTTP endpoints only occasionally
            if cycle % HTTP_POLL_EVERY == 0:
                try:
                    requests.get(f'http://{PV_HOST}/status', timeout=2)
                except Exception:
                    pass
                try:
                    requests.get(f'http://{PV_HOST}/admin/mqtt_data', timeout=2)
                except Exception:
                    pass
                # Occasionally create a new noisy device or update device names
                if random.random() < 0.02:
                    try:
                        requests.post(
                            f'http://{PV_HOST}/api/admin/devices',
                            json={'name': f'noise-{random.randint(0, 1000)}',
                                  'description': 'auto-device'},
                            timeout=2)
                    except Exception:
                        pass
        except Exception as e:
            print('noise loop err', e)
        cycle += 1
        time.sleep(LOOP_INTERVAL + random.uniform(0, LOOP_INTERVAL * 0.4))


if __name__ == '__main__':
    import sys
    if '--site' in sys.argv:
        idx = sys.argv.index('--site')
        target = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else ''
        # Each feeder needs its own MQTT client id — sharing one id makes the
        # broker disconnect the other clients on every connect.
        client = make_client(f'feeder-{target}')
        connect_mqtt()
        time.sleep(0.5)
        site_loop(target)
    if '--seed' in sys.argv:
        # Own client id: sharing one with the noise container made the broker
        # kick both sessions off, so the seed was published into the void.
        client = make_client('seed')
        # A failed seed is worse than a failed seed that says so: exit non-zero
        # so compose (restart: on-failure) retries instead of leaving the
        # dashboard with empty charts for the whole session.
        if not connect_mqtt():
            print(f'ABORT: could not reach MQTT broker at {MQTT_HOST}', flush=True)
            sys.exit(1)
        time.sleep(0.5)
        telemetry_ok = seed_telemetry(count=120)
        sites_ok = seed_site_history(count=60)
        if telemetry_ok and sites_ok:
            print('seeded telemetry', flush=True)
            sys.exit(0)
        print('ABORT: seed published with failures', flush=True)
        sys.exit(1)
    if '--seed-loop' in sys.argv:
        # What compose runs: seed, then keep the retained data fresh forever so
        # the dashboard is never left without site history.
        client = make_client('seed')
        connect_mqtt()
        seed_loop()
    client = make_client('noise')
    connect_mqtt()
    noise_loop()
