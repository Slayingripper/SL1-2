from pymodbus.client import ModbusTcpClient
import inspect

print(inspect.signature(ModbusTcpClient.write_coil))
