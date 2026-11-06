"""
Regenerate data.js from real VulnForge scan reports.

    python tools/make_data.py --vulnforge /path/to/VulnForge \
        --scan "Web scan::What it covers::/path/to/reports/VF-....json" \
        --scan "Port + CVE scan::What it covers::/path/to/reports/VF-....json"

Run it with the Python that has VulnForge's dependencies installed (its .venv),
because it imports core.verification_guide to attach the "how to verify" steps.
Reports are copied as they are, with long descriptions shortened. Check the
output for anything you would not want public (target names, paths) before
committing.
"""
import argparse, hashlib, json, re, sys
from pathlib import Path


def trim(text, n):
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    return text if len(text) <= n else text[: n - 1].rstrip() + "\u2026"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vulnforge", required=True, help="path to the VulnForge checkout")
    ap.add_argument("--scan", action="append", required=True, help='"label::blurb::report.json"')
    ap.add_argument("--out", default="data.js")
    args = ap.parse_args()

    sys.path.insert(0, args.vulnforge)
    from core.verification_guide import get_verification_steps

    guides, guide_list = {}, []

    def guide_id(finding):
        steps = get_verification_steps(finding)
        key = hashlib.md5(json.dumps(steps, sort_keys=True).encode()).hexdigest()
        if key not in guides:
            guides[key] = len(guide_list)
            guide_list.append({"tools": steps["tools"], "steps": steps["steps"]})
        return guides[key]

    scans = []
    for spec in args.scan:
        label, blurb, path = spec.split("::", 2)
        report = json.loads(Path(path).read_text(encoding="utf8"))
        findings = [
            {
                "title": trim(f["title"], 110), "sev": f["severity"], "conf": f.get("confidence", "high"),
                "src": f["source"], "desc": trim(f.get("description"), 260), "fix": trim(f.get("remediation"), 180),
                "ev": trim(f.get("evidence"), 160), "cat": f.get("category", ""), "g": guide_id(f),
                "cve": f.get("cve") or None,
            }
            for f in report["findings"]
        ]
        sm = report["summary"]
        scans.append({
            "label": label, "blurb": blurb, "id": report["scan_id"], "target": report["target"],
            "duration": report["duration"],
            "summary": {k: sm[k] for k in ("total_findings", "severity_counts", "open_ports", "risk_score", "web_checks", "hidden_low_confidence")},
            "ports": [{"port": k, "service": v.get("service"), "product": v.get("product"), "version": v.get("version")}
                      for k, v in report["port_scan"].get("ports", {}).items()],
            "findings": findings,
        })

    header = ("// Generated from two real VulnForge scans of a throwaway web server on the author's own machine.\n"
              "// Nothing here was invented; long descriptions are shortened.\n")
    out = (header + "window.SCANS = " + json.dumps(scans, indent=1, ensure_ascii=False) + ";\n"
           + "window.GUIDES = " + json.dumps(guide_list, indent=1, ensure_ascii=False) + ";\n")
    Path(args.out).write_text(out, encoding="utf8")
    print(f"wrote {args.out}: {len(scans)} scans, {sum(len(s['findings']) for s in scans)} findings, {len(guide_list)} guides")


if __name__ == "__main__":
    main()
