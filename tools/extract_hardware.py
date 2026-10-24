"""Export only hardware allowlist; bootargs/serials/MACs are never exported."""
import argparse
import hashlib
import json
from pathlib import Path
from fdt import FDT


def ranges(fdt, node):
    return [{"base": hex(a), "size": hex(s), "end_exclusive": hex(a + s)}
            for a, s in fdt.physical(node)]


def extract(data):
    f = FDT(data)
    report = {"schema": 1, "source": "analysis-only reconstructed FDT",
              "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
              "node_count": len(f.nodes), "ram": [], "reserved_memory": [],
              "memreserve": [{"base": hex(a), "size": hex(s)} for a, s in f.reservations],
              "cpus": [], "devices": []}
    wanted = ("arm,gic-v3", "arm,psci-0.2", "arm,armv8-timer",
              "sprd,sc9836-uart", "sprd,sdhc-r11p1", "sprd,dsi-host",
              "sprd,mali-gondul", "sprd,sc27xx-sys-timer", "sprd,sc9860-timer")
    for path, n in f.nodes.items():
        if n.strings("device_type") == ["memory"]:
            report["ram"].extend(ranges(f, n))
        if n.parent and n.parent.path == "/reserved-memory":
            entry = {"path": path, "reg": ranges(f, n),
                     "no-map": "no-map" in n.props, "reusable": "reusable" in n.props}
            for prop in ("size", "alignment", "alloc-ranges"):
                if prop in n.props:
                    entry[prop] = [hex(x) for x in n.cells(prop)]
            report["reserved_memory"].append(entry)
        if n.strings("device_type") == ["cpu"]:
            report["cpus"].append({"path": path, "compatible": n.strings("compatible"),
                                    "mpidr": [hex(a) for a, _ in f.reg(n)],
                                    "enable-method": n.strings("enable-method")})
        compat = n.strings("compatible")
        if (any(c in wanted for c in compat) or
                any(x in path.rsplit("/", 1)[-1] for x in ("usb@", "timer@", "i2c@")) and "reg" in n.props):
            entry = {"path": path, "compatible": compat, "status": n.strings("status"),
                     "reg": ranges(f, n), "interrupts": n.cells("interrupts", [])}
            for prop in ("method",):
                if prop in n.props:
                    entry[prop] = n.strings(prop)
            for prop in ("clock-frequency", "redistributor-stride", "bus-width"):
                if prop in n.props:
                    entry[prop] = n.cells(prop)
            report["devices"].append(entry)
    chosen = f.nodes["/chosen"]
    # Explicit stdout-path only; never copy bootargs or the rest of chosen.
    report["stdout-path"] = chosen.strings("stdout-path")
    stdout = report["stdout-path"][0].split(":")[0]
    if not stdout.startswith("/"):
        stdout = f.nodes["/aliases"].strings(stdout)[0]
    report["stdout_node"] = stdout
    return report


def main():
    p = argparse.ArgumentParser()
    p.add_argument("dtb", type=Path)
    p.add_argument("output", type=Path)
    a = p.parse_args()
    report = extract(a.dtb.read_bytes())
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Allowlisted {report['node_count']} nodes -> {a.output}")


if __name__ == "__main__":
    main()
