#!/usr/bin/env python3
import argparse, json, os, subprocess, sys, time, yaml, re
from pathlib import Path

# Optional deps
try:
    import requests
except Exception:
    requests = None
try:
    from prometheus_client import CollectorRegistry, Gauge, push_to_gateway
except Exception:
    CollectorRegistry = Gauge = push_to_gateway = None

SEV_LEVEL = {"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}

def run(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode not in (0,):  # trivy exit-code is 0 due to our flags
        print(p.stderr, file=sys.stderr)
    return p.returncode, p.stdout, p.stderr

def load_exceptions(path="config/exceptions.yaml"):
    if not os.path.exists(path):
        return {"ignore":{"cves":[],"packages":[],"images":[]}, "justifications":{}}
    with open(path) as f:
        return yaml.safe_load(f) or {}

def normalize_image(image):
    # separate name:tag (default tag latest)
    if ":" in image and not image.startswith("http"):
        name, tag = image.rsplit(":",1)
    else:
        name, tag = image, "latest"
    # registry inference for labels only
    registry = "docker.io"
    if "/" in name and "." in name.split("/")[0]:
        registry = name.split("/")[0]
    return name, tag, registry

def trivy_scan(image, ignore_unfixed):
    cmd = ["trivy","image","--scanners","vuln","--format","json","--no-progress","--timeout","5m","--quiet"]
    if ignore_unfixed:
        cmd += ["--ignore-unfixed"]
    cmd += [image]
    rc, out, err = run(cmd)
    if err.strip():
        print(err, file=sys.stderr)
    try:
        data = json.loads(out) if out.strip() else {}
    except json.JSONDecodeError:
        data = {}
    return data

def filter_and_count(data, image, exceptions, threshold):
    ignore = exceptions.get("ignore", {})
    ignore_cves = set(ignore.get("cves", []))
    ignore_pkgs = set(ignore.get("packages", []))
    ignore_imgs = set(ignore.get("images", []))

    sev_counts = {"LOW":0,"MEDIUM":0,"HIGH":0,"CRITICAL":0}
    offending = []
    threshold_num = SEV_LEVEL[threshold]
    fail = False

    results = data.get("Results", []) if isinstance(data, dict) else []
    for r in results:
        vulns = r.get("Vulnerabilities", []) or []
        for v in vulns:
            sid = v.get("VulnerabilityID","")
            sev = v.get("Severity","UNKNOWN").upper()
            pkg = v.get("PkgName","")
            if image in ignore_imgs or sid in ignore_cves or pkg in ignore_pkgs:
                continue
            if sev not in sev_counts:
                continue
            sev_counts[sev] += 1
            if SEV_LEVEL[sev] >= threshold_num:
                offending.append({
                    "id": sid,
                    "severity": sev,
                    "pkg": pkg,
                    "installed": v.get("InstalledVersion",""),
                    "fixed": v.get("FixedVersion",""),
                    "title": v.get("Title",""),
                    "primaryURL": v.get("PrimaryURL","")
                })
                fail = True
    return sev_counts, offending, fail

def write_reports(report_dir, image, sev_counts, offending, raw):
    Path(report_dir).mkdir(parents=True, exist_ok=True)
    ts = int(time.time())

    summary = {
        "image": image,
        "timestamp": ts,
        "severity_counts": sev_counts,
        "offending_sample": offending[:50],
    }
    with open(Path(report_dir)/"scan_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    with open(Path(report_dir)/"scan_raw.json", "w") as f:
        json.dump(raw, f, indent=2)

    # Simple HTML report
    html = [
        "<html><head><meta charset='utf-8'><title>Vulnerability Report</title>",
        "<style>body{font-family:system-ui,arial;margin:24px;}table{border-collapse:collapse;width:100%;}th,td{border:1px solid #ddd;padding:8px;}th{background:#f2f2f2;text-align:left;}</style>",
        "</head><body>",
        f"<h2>Vulnerability Report: {image}</h2>",
        f"<p><b>Generated:</b> {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))}</p>",
        "<h3>Severity Counts</h3>",
        "<ul>",
        *(f"<li>{k}: {v}</li>" for k,v in sev_counts.items()),
        "</ul>",
        "<h3>Top Findings</h3>",
        "<table><tr><th>ID</th><th>Severity</th><th>Package</th><th>Installed</th><th>Fixed</th><th>Title</th></tr>",
    ]
    for v in offending[:100]:
        title = (v.get("title") or "").replace("<","&lt;")[:120]
        html.append(f"<tr><td><a href='{v.get('primaryURL','')}'>{v['id']}</a></td><td>{v['severity']}</td><td>{v['pkg']}</td><td>{v['installed']}</td><td>{v['fixed']}</td><td>{title}</td></tr>")
    html.append("</table></body></html>")
    with open(Path(report_dir)/"report.html", "w") as f:
        f.write("\n".join(html))

def notify_slack(slack_url, image, sev_counts, offending):
    if not slack_url or not requests:
        return
    txt = f"*Image:* `{image}`\n*Counts:* {sev_counts}\n*Blocking Findings:* {len(offending)}"
    payload = {"text": txt}
    try:
        requests.post(slack_url, json=payload, timeout=10)
    except Exception:
        pass

def notify_teams(teams_url, image, sev_counts, offending):
    if not teams_url or not requests:
        return
    payload = {"text": f"Image: {image}\nCounts: {sev_counts}\nBlocking Findings: {len(offending)}"}
    try:
        requests.post(teams_url, json=payload, timeout=10)
    except Exception:
        pass

def push_metrics(pushgateway, image, sev_counts):
    if not pushgateway or not CollectorRegistry:
        return
    name, tag, registry = normalize_image(image)
    reg = CollectorRegistry()
    for sev, val in sev_counts.items():
        g = Gauge("vuln_count", "Vulnerabilities by severity", ["image","tag","registry","severity"], registry=reg)
        g.labels(name, tag, registry, sev).set(val)
    try:
        push_to_gateway(pushgateway, job="vulnerability_scan", registry=reg)
    except Exception:
        pass

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True)
    ap.add_argument("--report-dir", default="reports")
    ap.add_argument("--severity-threshold", default="HIGH", choices=list(SEV_LEVEL.keys()))
    ap.add_argument("--ignore-unfixed", action="store_true")
    args = ap.parse_args()

    slack = os.getenv("SLACK_WEBHOOK_URL","")
    teams = os.getenv("TEAMS_WEBHOOK_URL","")
    pushgw = os.getenv("PUSHGATEWAY_URL","")

    exceptions = load_exceptions()
    raw = trivy_scan(args.image, args.ignore_unfixed)
    sev_counts, offending, fail = filter_and_count(raw, args.image, exceptions, args.severity_threshold)
    write_reports(args.report_dir, args.image, sev_counts, offending, raw)
    notify_slack(slack, args.image, sev_counts, offending)
    notify_teams(teams, args.image, sev_counts, offending)
    push_metrics(pushgw, args.image, sev_counts)

    if fail:
        print(f"Blocking vulnerabilities found at/above {args.severity_threshold}.", file=sys.stderr)
        sys.exit(1)
    print("Scan passed.")
    sys.exit(0)

if __name__ == "__main__":
    main()

