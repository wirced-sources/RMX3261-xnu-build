"""Small strict ELF64/LE reader used to audit freestanding AArch64 output."""
import struct


class ELF:
    def __init__(self, data):
        self.data = data
        h = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
        if h[0][:7] != b"\x7fELF\x02\x01\x01" or h[2] != 183:
            raise ValueError("expected little-endian ELF64 AArch64")
        self.entry = h[4]
        off, size, count, names = h[6], h[11], h[12], h[13]
        if size != 64 or off + size * count > len(data):
            raise ValueError("invalid section table")
        sections = [struct.unpack_from("<IIQQQQIIQQ", data, off + i * size) for i in range(count)]
        ns = sections[names]
        strings = data[ns[4]:ns[4] + ns[5]]
        self.sections = []
        for s in sections:
            if s[1] != 8 and s[4] + s[5] > len(data):
                raise ValueError("section beyond EOF")
            name = strings[s[0]:].split(b"\0", 1)[0].decode()
            self.sections.append(dict(name=name, type=s[1], flags=s[2], addr=s[3],
                                      offset=s[4], size=s[5], link=s[6], entsize=s[9]))

    def content(self, section):
        return self.data[section["offset"]:section["offset"] + section["size"]]

    def symbols(self):
        result = {}
        for s in self.sections:
            if s["type"] != 2:
                continue
            strings = self.content(self.sections[s["link"]])
            for p in range(0, s["size"], 24):
                n, info, other, sh, val, sz = struct.unpack_from("<IBBHQQ", self.content(s), p)
                name = strings[n:].split(b"\0", 1)[0].decode()
                if name:
                    result[name] = (val, sh)
        return result

    def audit_object(self, header=False):
        for s in self.sections:
            if s["type"] != 4:
                continue
            for p in range(0, s["size"], 24):
                off, info, _ = struct.unpack_from("<QQq", self.content(s), p)
                kind = info & 0xffffffff
                # ABS64 only for the Image size in start.S; PC-relative code elsewhere.
                if kind == 257 and header and s["name"] == ".rela.text.head" and off == 16:
                    continue
                if kind not in (260, 261, 273, 274, 275, 277, 278, 279, 280, 282, 283, 284, 285, 286, 299):
                    raise ValueError(f"non-PC-relative/unsupported relocation {kind} at {s['name']}+{off:#x}")
