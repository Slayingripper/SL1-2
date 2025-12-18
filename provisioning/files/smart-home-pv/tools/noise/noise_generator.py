import time
import os
import json
import requests
import random
import paho.mqtt.client as mqtt

MQTT_HOST = os.environ.get('MQTT_HOST', 'mosquitto')
PV_HOST = os.environ.get('PV_HOST', 'pv-controller')

client = mqtt.Client(client_id='noise-generator')

try:
    client.connect(MQTT_HOST, 1883, 60)
except Exception as e:
    print('MQTT connect failed', e)

# publish sensor data and occasionally hit admin dashboard and status
while True:
    try:
        # MQTT: publish telemetry
        payload = {'ts': time.time(), 'value': random.randint(0,100)}
        client.publish('pv/telemetry', json.dumps(payload))
        # poll status
        try:
            requests.get(f'http://{PV_HOST}/status', timeout=2)
        except Exception:
            pass
        # hit admin telemetry endpoint
        try:
            requests.get(f'http://{PV_HOST}/admin/mqtt_data', timeout=2)
        except Exception:
            pass
        # Occasionally create a new noisy device or update device names
        if random.random() < 0.05:
            try:
                requests.post(f'http://{PV_HOST}/api/admin/devices', json={'name': f'noise-{random.randint(0,1000)}', 'description': 'auto-device'})
            except Exception:
                pass
    except Exception as e:
        print('noise loop err', e)
    time.sleep(1)

def seed_telemetry(count=60, host='localhost'):
    # Send a burst of telemetry messages to fill the chart on startup
    try:
        for i in range(count):
            payload = {'ts': time.time(), 'value': random.randint(500, 3500), 'power': random.randint(500, 3500)}
            client.publish('pv/telemetry', json.dumps(payload))
            time.sleep(0.05)
    except Exception as e:
        print('seed_telemetry failed', e)

if __name__ == '__main__':
    import sys
    # If called with --seed, seed telemetry and exit
    if '--seed' in sys.argv:
        seed_telemetry(count=120, host=MQTT_HOST)
        print('seeded telemetry')
        sys.exit(0)
