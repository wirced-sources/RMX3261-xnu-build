"""Strict offline FDT v17 reader. Never dump arbitrary properties to reports."""
from dataclasses import dataclass, field
import struct


class FDTError(ValueError):
    pass


@dataclass
class Node:
    path: str
    parent: object = None
    props: dict = field(default_factory=dict)

    def cells(self, name, default=None):
        b = self.props.get(name)
        if b is None:
            return default
        if len(b) % 4:
            raise FDTError("unaligned cells")
        return list(struct.unpack(">" + "I" * (len(b) // 4), b))

    def strings(self, name):
        b = self.props.get(name, b"")
        if b and not b.endswith(b"\0"):
            raise FDTError("unterminated property string")
        return b.rstrip(b"\0").decode("ascii").split("\0") if b else []

    def width(self, name, default):
        c = self.cells(name, [default])
        if len(c) != 1 or c[0] > 4:
            raise FDTError("unsupported cell width")
        return c[0]


def number(cells):
    v = 0
    for c in cells:
        v = (v << 32) | c
    return v


class FDT:
    def __init__(self, data):
        if len(data) < 40:
            raise FDTError("short header")
        magic, total, so, st, ro, ver, last, _, sl, sz = struct.unpack_from(">10I", data)
        if magic != 0xd00dfeed or total != len(data) or ver != 17 or last > 17:
            raise FDTError("not an exact v17 FDT")
        if so % 4 or ro % 8 or min(so, st, ro) < 40:
            raise FDTError("invalid block offset")
        if so + sz > total or st + sl > total or not (so + sz <= st or st + sl <= so):
            raise FDTError("invalid/overlapping blocks")
        self.reservations = []
        p = ro
        while True:
            if p + 16 > min(so, st):
                raise FDTError("unterminated reserve map")
            addr, size = struct.unpack_from(">QQ", data, p)
            p += 16
            if not (addr or size):
                break
            self.reservations.append((addr, size))
        self.nodes = {}
        stack = []
        p, end = so, so + sz
        strings = data[st:st + sl]
        ended = False
        while p + 4 <= end:
            tok = struct.unpack_from(">I", data, p)[0]
            p += 4
            if tok == 1:
                e = data.find(b"\0", p, end)
                if e < 0:
                    raise FDTError("unterminated node")
                name = data[p:e].decode("ascii")
                if "/" in name or (not stack and (name or self.nodes)):
                    raise FDTError("invalid root/name")
                path = (stack[-1].path.rstrip("/") + "/" + name) if stack else "/"
                if path in self.nodes or len(stack) > 64:
                    raise FDTError("duplicate/deep node")
                node = Node(path, stack[-1] if stack else None)
                self.nodes[path] = node
                stack.append(node)
                p = (e + 4) & ~3
            elif tok == 2:
                if not stack:
                    raise FDTError("unbalanced end node")
                stack.pop()
            elif tok == 3:
                if not stack or p + 8 > end:
                    raise FDTError("invalid property")
                ln, off = struct.unpack_from(">II", data, p)
                p += 8
                if p + ln > end or off >= sl:
                    raise FDTError("property out of bounds")
                e = strings.find(b"\0", off)
                if e < 0:
                    raise FDTError("unterminated property name")
                name = strings[off:e].decode("ascii")
                if name in stack[-1].props:
                    raise FDTError("duplicate property")
                stack[-1].props[name] = data[p:p + ln]
                p = (p + ln + 3) & ~3
            elif tok == 4:
                pass
            elif tok == 9:
                if stack or not self.nodes:
                    raise FDTError("unbalanced FDT_END")
                ended = True
                break
            else:
                raise FDTError("unknown token")
        if not ended:
            raise FDTError("missing FDT_END")

    def reg(self, node):
        bus = node.parent
        if bus is None:
            return []
        ac, sc = bus.width("#address-cells", 2), bus.width("#size-cells", 1)
        cells = node.cells("reg", [])
        stride = ac + sc
        if not stride or len(cells) % stride:
            raise FDTError("bad reg")
        return [(number(cells[i:i + ac]), number(cells[i + ac:i + stride]))
                for i in range(0, len(cells), stride)]

    def physical(self, node):
        result = []
        for address, size in self.reg(node):
            bus = node.parent
            while bus and bus.parent:
                # reserved-memory follows root addressing with empty ranges.
                if "ranges" not in bus.props:
                    raise FDTError("unmapped bus: " + bus.path)
                r = bus.cells("ranges")
                if r:
                    ac = bus.width("#address-cells", 2)
                    pc = bus.parent.width("#address-cells", 2)
                    sc = bus.width("#size-cells", 1)
                    stride = ac + pc + sc
                    if len(r) % stride:
                        raise FDTError("bad ranges")
                    for i in range(0, len(r), stride):
                        child = number(r[i:i + ac])
                        parent = number(r[i + ac:i + ac + pc])
                        length = number(r[i + ac + pc:i + stride])
                        if child <= address and address + size <= child + length:
                            address = parent + address - child
                            break
                    else:
                        raise FDTError("reg outside ranges")
                bus = bus.parent
            result.append((address, size))
        return result
