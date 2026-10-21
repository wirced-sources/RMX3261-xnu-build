"""Offline doconf attribute expansion for the deliberately restricted UMS512 MASTER.

SETUP/config still parses the result and generates headers. Reject preprocessor
directives/unknown syntax rather than pretending to implement unifdef/csh.
"""
import re


def configure(master, board, variant="DEVELOPMENT"):
    text = master + "\n" + board
    if re.search(r"^\s*#\s*(if|else|elif|endif)\b", text, re.M):
        raise ValueError("preprocessed MASTER requires upstream doconf/unifdef")
    groups = {m[1]: m[2].split() for m in re.finditer(r"^#\s*(\w+)\s*=\s*\[([^\]]*)\]", text, re.M)}
    if variant not in groups:
        raise ValueError("unknown configuration")
    features = set()

    def expand(name, chain=()):
        if name in chain:
            raise ValueError("cyclic MASTER group")
        if name in groups:
            for item in groups[name]:
                expand(item, (*chain, name))
        else:
            features.add(name)

    expand(variant)
    lines = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.search(r"#\s*<(!?)([^>]+)>\s*$", line)
        if match:
            selected = bool(set(match[2].split(",")) & features)
            if selected == bool(match[1]):
                continue
        lines.append(line.split("#", 1)[0].rstrip())
    return "\n".join(lines) + "\n", sorted(features)
