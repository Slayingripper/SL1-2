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

client = mqtt.Client(client_id='noise-generator')


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
    if '--seed' in sys.argv:
        connect_mqtt()
        time.sleep(0.5)
        seed_telemetry(count=120)
        print('seeded telemetry')
        sys.exit(0)
    connect_mqtt()
    noise_loop()
