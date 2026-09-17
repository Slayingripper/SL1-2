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

client = mqtt.Client(client_id='noise-generator')

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
    for site in SITES:
        try:
            client.publish(f"pv/telemetry/{site['id']}",
                           json.dumps(site_sample(site, now)), retain=True)
        except Exception as e:
            print('site publish failed', e)


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
    try:
        client.publish(f'pv/history/{site_id}',
                       json.dumps({'site': site_id, 'points': points, 'seeder': info}),
                       retain=True)
    except Exception as e:
        print('history seed failed', e)

    seq = 0
    while True:
        seq += 1
        now = time.time()
        payload = site_sample(site, now)
        payload['seeder'] = dict(info, seq=seq, uptime_s=round(now - started, 1))
        try:
            client.publish(f'pv/telemetry/{site_id}', json.dumps(payload), retain=True)
        except Exception as e:
            print('site publish failed', e)
        time.sleep(SITE_INTERVAL + random.uniform(0, SITE_INTERVAL * 0.3))


def seed_site_history(count=60):
    """Retained per-site history so map sparklines are full on first load."""
    now = time.time()
    for site in SITES:
        points = [site_sample(site, now - (count - 1 - i) * 60) for i in range(count)]
        try:
            client.publish(f"pv/history/{site['id']}",
                           json.dumps({'site': site['id'], 'points': points}), retain=True)
        except Exception as e:
            print('history seed failed', e)
        time.sleep(0.05)
    publish_sites(now)


def connect_mqtt():
    try:
        client.connect(MQTT_HOST, 1883, 60)
        client.loop_start()
        return True
    except Exception as e:
        print('MQTT connect failed', e)
        return False


def seed_telemetry(count=60):
    """Send a burst of realistic daytime PV telemetry to fill the chart on startup."""
    base = time.time() - count * 60
    for i in range(count):
        # Bell-ish solar production curve scaled to a residential system (kW)
        phase = i / max(1, count - 1)
        curve = max(0.12, pow(phase, 0.6) * pow(1.0 - phase, 0.25))
        power_kw = round(random.uniform(2.8, 4.6) * curve + 0.15, 3)
        payload = {'ts': base + i * 60, 'power_kw': power_kw}
        try:
            client.publish('pv/telemetry', json.dumps(payload))
        except Exception as e:
            print('seed publish failed', e)
            break
        time.sleep(0.05)


def noise_loop():
    cycle = 0
    while True:
        try:
            # MQTT: publish background sensor noise
            payload = {'ts': time.time(), 'value': random.randint(0, 100)}
            client.publish('pv/telemetry', json.dumps(payload))

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
        client = mqtt.Client(client_id=f'feeder-{target}')
        connect_mqtt()
        time.sleep(0.5)
        site_loop(target)
    if '--seed' in sys.argv:
        connect_mqtt()
        time.sleep(0.5)
        seed_telemetry(count=120)
        seed_site_history(count=60)
        print('seeded telemetry')
        sys.exit(0)
    connect_mqtt()
    noise_loop()
