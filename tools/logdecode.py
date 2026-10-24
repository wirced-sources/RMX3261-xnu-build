"""Decode a copied M0 RAM ring. It is volatile; no persistence is promised."""
import argparse
from pathlib import Path
import struct
import re


def test_tag(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-fA-F]{32}', value) or int(value,16)==0:
        raise ValueError('test tag must be a nonzero 128-bit value encoded as 32 hex digits')
    return value.lower()


def decode(data, expected_tag=None):
    if len(data) < 40:
        raise ValueError("short log header")
    magic, version, capacity, head, total, stage, dropped, reserved = struct.unpack_from("<4I2Q2I", data)
    if magic != 0x30584d52 or version != 1 or capacity != 4096 or reserved:
        raise ValueError("invalid log ABI")
    if len(data) != 40 + capacity or head >= capacity or head != total % capacity:
        raise ValueError("invalid/truncated or torn ring")
    payload = data[40:]
    text = payload[:head] if total < capacity else payload[head:] + payload[:head]
    result = {"stage": stage, "total": total, "uart_dropped": dropped,
              "text": text.decode("ascii", errors="replace")}
    if expected_tag is not None:
        wanted = test_tag(expected_tag)
        observed = re.findall(r'^TEST_TAG=([0-9a-f]{32})$', result['text'], re.M)
        if observed != [wanted]: raise ValueError('missing, stale or ambiguous test tag')
        result.update(test_tag=wanted, test_tag_verified=True)
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("dump", type=Path)
    p.add_argument('--expect-tag', type=test_tag, help='require the exact per-test manifest tag')
    a = p.parse_args()
    result = decode(a.dump.read_bytes(), a.expect_tag)
    print(f"stage={result['stage']:#x} total={result['total']} dropped={result['uart_dropped']}")
    print(result["text"], end="")
