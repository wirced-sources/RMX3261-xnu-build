"""Decode a copied M0 RAM ring. It is volatile; no persistence is promised."""
import argparse
from pathlib import Path
import struct
import re


def test_tag(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-fA-F]{32}', value) or int(value,16)==0:
        raise ValueError('test tag must be a nonzero 128-bit value encoded as 32 hex digits')
    return value.lower()


def decode_probe(data,expected_tag):
    """A completed local snapshot proves format/identity, not device attestation."""
    if len(data)!=192:raise ValueError('entry snapshot must be exactly 192 bytes')
    words=struct.unpack('<24Q',data)
    if words[:4]!=(0x31425250,1,192,0x512) or words[-1]:
        raise ValueError('invalid/incomplete entry snapshot')
    tag=struct.pack('<2Q',*words[4:6]).hex()
    if tag!=test_tag(expected_tag):raise ValueError('stale entry snapshot identity')
    names=('x0','x1','x2','x3','sp','lr','current_el','daif','nzcv','sctlr',
           'midr','mpidr','mmfr0','mmfr1','ctr','vbar','entry_pc')
    if words[12] not in (4,8) or words[15]&(1<<25):
        raise ValueError('unsupported snapshot EL/endianness')
    return dict(scope='M0 returning snapshot; not XNU/hardware qualification',test_tag=tag,
        registers={n:hex(v) for n,v in zip(names,words[6:23])},hardware_verified=False)


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
    p.add_argument('--entry-probe',action='store_true',help='decode returning snapshot; --expect-tag required')
    a = p.parse_args()
    if a.entry_probe:
        if a.expect_tag is None:p.error('--entry-probe requires --expect-tag')
        import json
        print(json.dumps(decode_probe(a.dump.read_bytes(),a.expect_tag),indent=2))
        raise SystemExit(0)
    result = decode(a.dump.read_bytes(), a.expect_tag)
    print(f"stage={result['stage']:#x} total={result['total']} dropped={result['uart_dropped']}")
    print(result["text"], end="")
