"""Plist validation helper for BLADE adversarial plist tests.
Usage: python validate.py <file> -> JSON verdict on stdout.
Checks: plistlib semantic parse (xml1 + binary), XML well-formedness via expat,
and recursively collects any dict keys containing 'BLA'."""
import sys, json, plistlib
import xml.etree.ElementTree as ET

def walk_keys(obj, acc):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).startswith("BLA"):
                acc.append(str(k))
            walk_keys(v, acc)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            walk_keys(v, acc)

def main():
    path = sys.argv[1]
    raw = open(path, "rb").read()
    out = {"file": path.split("/")[-1].split("\\")[-1], "bytes": len(raw)}
    try:
        obj = plistlib.loads(raw)
        out["plistlib"] = "ok"
        acc = []
        walk_keys(obj, acc)
        out["bla_keys"] = acc
        if isinstance(obj, dict):
            out["top_keys"] = sorted(str(k) for k in obj.keys())
    except Exception as e:
        out["plistlib"] = f"FAIL: {type(e).__name__}: {e}"
    try:
        ET.fromstring(raw.decode("utf-8"))
        out["xml_wf"] = "ok"
    except Exception as e:
        out["xml_wf"] = f"FAIL: {e}"
    print(json.dumps(out))

main()
