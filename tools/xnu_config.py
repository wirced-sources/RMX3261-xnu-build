"""Offline doconf attribute expansion for the deliberately restricted UMS512 MASTER.

SETUP/config still parses the result and generates headers. Reject preprocessor
directives/unknown syntax rather than pretending to implement unifdef/csh.
"""
import re
import shlex
import subprocess


def enforcement_probe(makefile, kern_cs, compiler):
    """Check real SETUP/config output against the unchanged kern_cs initializer."""
    match=re.search(r'^export CONFIG_DEFINES =([^\n]+)', makefile, re.M)
    if not match:
        raise ValueError('SETUP/config CONFIG_DEFINES missing')
    options=shlex.split(match[1])
    selected=[o for o in options if o.startswith('-DCONFIG_ENFORCE_SIGNED_CODE')]
    if selected!=['-DCONFIG_ENFORCE_SIGNED_CODE']:
        raise ValueError('actual SETUP/config did not enable signed-code enforcement')
    block=re.search(r'^#if CONFIG_ENFORCE_SIGNED_CODE\n.*?^#endif',kern_cs,re.M|re.S)
    if not block:
        raise ValueError('upstream kern_cs enforcement initializer changed')
    source=block[0]+'\nint probe = DEFAULT_CS_PROCESS_ENFORCEMENT_ENABLE;\n'
    values=[]
    for flags in ([],selected):
        result=subprocess.run([*compiler,'-E','-P','-x','c',*flags,'-'],input=source,
                              text=True,capture_output=True,check=True,timeout=30)
        values.append(result.stdout.strip())
    if values!=['int probe = 0;','int probe = 1;']:
        raise ValueError('real compiler did not preserve upstream enforcement semantics')
    return dict(config_define=selected[0],stock_initializer=1,missing_option_negative_control=0,
                source='unchanged bsd/kern/kern_cs.c',guest_state_modified=False)


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
