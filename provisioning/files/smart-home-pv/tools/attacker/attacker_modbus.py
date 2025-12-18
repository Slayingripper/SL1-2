#!/usr/bin/env python3
# Simple Modbus write client to set coil 1 to 1
# Updated for pymodbus 3.x API
from pymodbus.client import ModbusTcpClient
import sys

host = sys.argv[1] if len(sys.argv) > 1 else '172.20.0.65'
port = int(sys.argv[2]) if len(sys.argv) > 2 else 15002

print(f"Connecting to Modbus server: {host}:{port}")
client = ModbusTcpClient(host, port=port)
if client.connect():
    print(f"Connection established")
    print(f"Writing coil 1 = TRUE (HALT command)")
    print(f"Function Code: 0x05 (Write Single Coil)")
    print(f"Address: 0x0001")
    print(f"Value: 0xFF00 (TRUE)")
    rr = client.write_coil(1, True)
    print(f"Response: {rr}")
    print(f"Transaction ID: {rr.transaction_id if hasattr(rr, 'transaction_id') else 'N/A'}")
    print(f"Status: {'SUCCESS' if not rr.isError() else 'ERROR'}")
    client.close()
    print(f"Connection closed")
else:
    print(f"Failed to connect to {host}:{port}")
    sys.exit(1)

