#!/usr/bin/env python3
"""Teaching Modbus client (pymodbus 3.x)

Purpose:
  - Demonstrate how changing a small set of Modbus PDU fields (address/value)
    changes the effect of a write.

This script is for authorized lab usage.
"""

from __future__ import annotations

import argparse
import os
import sys

from pymodbus.client import ModbusTcpClient


def _env_int(name: str, default: int) -> int:
    val = os.environ.get(name)
    if val is None or val == "":
        return default
    try:
        return int(val, 0)
    except ValueError:
        raise SystemExit(f"Invalid {name}={val!r} (expected int, supports 0x..)")


def _env_bool01(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None or val == "":
        return default
    if val in {"1", "true", "True", "yes", "on"}:
        return True
    if val in {"0", "false", "False", "no", "off"}:
        return False
    raise SystemExit(f"Invalid {name}={val!r} (expected 0/1/true/false)")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Write a Modbus coil and print a packet-field breakdown (lab teaching tool).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("host", nargs="?", default="172.20.0.65")
    parser.add_argument("port", nargs="?", type=int, default=15002)
    parser.add_argument(
        "--unit",
        type=int,
        default=_env_int("MODBUS_UNIT_ID", 1),
        help="Modbus Unit/Slave ID (also from MODBUS_UNIT_ID)",
    )
    parser.add_argument(
        "--coil",
        type=int,
        default=_env_int("MODBUS_COIL_ADDR", 1),
        help="Coil address to write (also from MODBUS_COIL_ADDR)",
    )
    parser.add_argument(
        "--value",
        type=int,
        choices=[0, 1],
        default=1 if _env_bool01("MODBUS_COIL_VALUE", True) else 0,
        help="Coil value: 1=ON, 0=OFF (also from MODBUS_COIL_VALUE)",
    )
    args = parser.parse_args(argv)

    host: str = args.host
    port: int = args.port
    unit: int = args.unit
    coil_addr: int = args.coil
    coil_value: bool = bool(args.value)

    print(f"Connecting to Modbus server: {host}:{port}")
    print("\n=== Packet fields you control ===")
    print("Function Code: 0x05  (Write Single Coil)")
    print(f"Unit/Slave ID: {unit}  (Routing inside the Modbus server)")
    print(f"Coil Address : {coil_addr}  (Which discrete output you are flipping)")
    print(f"Coil Value   : {int(coil_value)}  (1=ON, 0=OFF)")

    # In Modbus Write Single Coil semantics, ON is encoded as 0xFF00 and OFF as 0x0000.
    encoded = "0xFF00" if coil_value else "0x0000"
    print(f"Encoded Value: {encoded}  (Protocol-level representation)")
    print(
        "Why this matters: changing just the address/value bytes changes what physical/control point"
        " you affect — there is often no authentication at this layer.\n"
    )

    client = ModbusTcpClient(host, port=port)
    if not client.connect():
        print(f"Failed to connect to {host}:{port}")
        return 1

    print("Connection established")
    rr = client.write_coil(coil_addr, coil_value, slave=unit)

    print("\n=== Response ===")
    print(f"Response: {rr}")
    tid = getattr(rr, "transaction_id", None)
    if tid is not None:
        print(f"Transaction ID: {tid}")
    print(f"Status: {'SUCCESS' if not rr.isError() else 'ERROR'}")

    client.close()
    print("Connection closed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

