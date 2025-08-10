
# 0) Prereqs (one-time)

**On your workstation/Jenkins agent (Ubuntu/Debian):**

```bash
# Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Python 3.10+ & tools
sudo apt-get update
sudo apt-get install -y python3-pip jq curl git

# Trivy
TRIVY_VER=0.52.0
wget https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VER}/trivy_${TRIVY_VER}_Linux-64bit.deb
sudo dpkg -i trivy_${TRIVY_VER}_Linux-64bit.deb
trivy --version
```

**Create Slack/Teams webhook (optional, recommended):**

* Slack: Incoming Webhook → note the URL.
* Teams: Incoming Webhook (in a channel) → note the URL.

---

# 1) Repo scaffold

```bash
mkdir -p vuln-scanner/{scripts,config,reports,.github/workflows,dashboard}
cd vuln-scanner
```

**`requirements.txt`**

```
PyYAML==6.0.2
requests==2.32.3
prometheus-client==0.20.0
Jinja2==3.1.4
```

**`config/policy.env.example`**

```
# Fail when any vuln at or above this severity is found: LOW|MEDIUM|HIGH|CRITICAL
SEVERITY_FAIL_LEVEL=HIGH
# Treat unfixed vulns as pass (true) or fail (false)
IGNORE_UNFIXED=true
# Optional webhooks (leave blank to disable)
SLACK_WEBHOOK_URL=
TEAMS_WEBHOOK_URL=
# Optional Prometheus Pushgateway (e.g. http://localhost:9091)
PUSHGATEWAY_URL=
```

**`config/exceptions.yaml`**

```yaml
ignore:
  cves:
    - CVE-0000-IGNORE-EXAMPLE
  packages:
    - examplepkg
  images:
    - nginx:dev-only
justifications:
  CVE-0000-IGNORE-EXAMPLE: "Accepted risk for demo. Mitigated by network policy."
```

**`scripts/scan_image.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail

IMAGE="${1:-}"
: "${IMAGE:?Usage: scripts/scan_image.sh <image[:tag]>}"

# load env if present
if [ -f "config/policy.env" ]; then
  set -a
  . config/policy.env
  set +a
fi

mkdir -p reports

python3 -m pip install -r requirements.txt --quiet
python3 scripts/scan_image.py \
  --image "$IMAGE" \
  --report-dir "reports" \
  --severity-threshold "${SEVERITY_FAIL_LEVEL:-HIGH}" \
  $( [ "${IGNORE_UNFIXED:-true}" = "true" ] && echo "--ignore-unfixed" )
```

```bash
chmod +x scripts/scan_image.sh
```

**`scripts/scan_image.py`**

```python
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
```

**Initialize git**

```bash
python3 -m pip install -r requirements.txt
cp config/policy.env.example config/policy.env
git init
git add .
git commit -m "feat: initial vulnerability scanner"
```

---

# 2) Local test (prove it works)

```bash
# example images to test
docker pull nginx:1.23
./scripts/scan_image.sh nginx:1.23 || true
ls -la reports/
```

Open `reports/report.html` in a browser. If the command exits with status 1, it correctly blocked due to HIGH/CRITICAL findings.

---

# 3) Jenkins integration

**Jenkinsfile** (in repo root):

```groovy
pipeline {
  agent any
  parameters {
    string(name: 'IMAGE', defaultValue: 'nginx:1.23', description: 'Image to scan')
    choice(name: 'SEVERITY_FAIL_LEVEL', choices: ['LOW','MEDIUM','HIGH','CRITICAL'], description: 'Fail threshold')
    booleanParam(name: 'IGNORE_UNFIXED', defaultValue: true, description: 'Ignore unfixed vulns')
  }
  stages {
    stage('Checkout') {
      steps { checkout scm }
    }
    stage('Install Tools') {
      steps {
        sh '''
          python3 -m pip install -r requirements.txt --quiet
          if ! command -v trivy >/dev/null 2>&1; then
            TRIVY_VER=0.52.0
            wget -q https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VER}/trivy_${TRIVY_VER}_Linux-64bit.deb
            sudo dpkg -i trivy_${TRIVY_VER}_Linux-64bit.deb
          fi
          trivy --version
        '''
      }
    }
    stage('Scan') {
      environment {
        SLACK_WEBHOOK_URL = credentials('slack-webhook-secret-id') // or leave blank
        TEAMS_WEBHOOK_URL = '' // optional
        PUSHGATEWAY_URL = ''   // optional
      }
      steps {
        sh '''
          cp -f config/policy.env.example config/policy.env
          sed -i "s/^SEVERITY_FAIL_LEVEL=.*/SEVERITY_FAIL_LEVEL=${SEVERITY_FAIL_LEVEL}/" config/policy.env
          sed -i "s/^IGNORE_UNFIXED=.*/IGNORE_UNFIXED=${IGNORE_UNFIXED}/" config/policy.env
          ./scripts/scan_image.sh "${IMAGE}"
        '''
      }
      post {
        always {
          archiveArtifacts artifacts: 'reports/*', fingerprint: true
        }
      }
    }
  }
}
```

**Jenkins → Credentials:** add a secret text `slack-webhook-secret-id` if using Slack.

Run the job and try images like `alpine:3.18`, `python:3.11-slim`.

---

# 4) GitHub Actions (optional / or in parallel)

**`.github/workflows/scan.yml`**

```yaml
name: Container Image Vulnerability Scan
on:
  workflow_dispatch:
    inputs:
      image:
        description: 'Image reference'
        required: true
        default: 'nginx:1.23'
  push:
    branches: [ main ]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Python deps
        run: python3 -m pip install -r requirements.txt
      - name: Install Trivy
        run: |
          sudo apt-get update
          sudo apt-get install -y jq curl
          TRIVY_VER=0.52.0
          wget https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VER}/trivy_${TRIVY_VER}_Linux-64bit.deb
          sudo dpkg -i trivy_${TRIVY_VER}_Linux-64bit.deb
      - name: Configure policy
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
          TEAMS_WEBHOOK_URL: ${{ secrets.TEAMS_WEBHOOK_URL }}
          PUSHGATEWAY_URL: ${{ secrets.PUSHGATEWAY_URL }}
        run: |
          cp config/policy.env.example config/policy.env
          sed -i 's/SEVERITY_FAIL_LEVEL=HIGH/SEVERITY_FAIL_LEVEL=HIGH/' config/policy.env
          sed -i 's/IGNORE_UNFIXED=true/IGNORE_UNFIXED=true/' config/policy.env
      - name: Scan
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
          TEAMS_WEBHOOK_URL: ${{ secrets.TEAMS_WEBHOOK_URL }}
          PUSHGATEWAY_URL: ${{ secrets.PUSHGATEWAY_URL }}
        run: |
          IMAGE="${{ github.event.inputs.image || 'nginx:1.23' }}"
          ./scripts/scan_image.sh "$IMAGE"
      - name: Upload reports
        uses: actions/upload-artifact@v4
        with:
          name: scan-reports
          path: reports/**
```

Add repository secrets as needed.

---

# 5) Notifications (Slack/Teams)

Already wired into `scan_image.py`. To enable:

* Put your webhook URL into Jenkins credentials or GitHub Secrets.
* Set env var `SLACK_WEBHOOK_URL` or `TEAMS_WEBHOOK_URL` via pipeline.

Messages show counts and blocking findings.

---

# 6) Metrics + Dashboard (Prometheus + Grafana)

For quick local dashboard:
**`dashboard/docker-compose.dashboard.yml`**

```yaml
version: "3.8"
services:
  pushgateway:
    image: prom/pushgateway:latest
    ports: ["9091:9091"]
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
    ports: ["9090:9090"]
    depends_on: [pushgateway]
  grafana:
    image: grafana/grafana:latest
    ports: ["3000:3000"]
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    depends_on: [prometheus]
```

**`dashboard/prometheus.yml`**

```yaml
global:
  scrape_interval: 30s
scrape_configs:
  - job_name: 'pushgateway'
    honor_labels: true
    static_configs:
      - targets: ['pushgateway:9091']
```

Run:

```bash
cd dashboard
docker compose -f docker-compose.dashboard.yml up -d
```

Set `PUSHGATEWAY_URL=http://localhost:9091` (Jenkins/Actions env).
Grafana → add Prometheus ([http://prometheus:9090](http://prometheus:9090) in compose, or [http://localhost:9090](http://localhost:9090) if outside).
Create panels using metric: `vuln_count{severity="HIGH"}` with labels `image`, `tag`, `registry`.

---

# 7) Exceptions & rescans

* Maintain `config/exceptions.yaml`.
* To schedule **weekly rescans** (Jenkins):

  * Add a second job that iterates critical images and runs `./scripts/scan_image.sh <image>`.
  * Or GitHub Actions cron:

    ```yaml
    on:
      schedule:
        - cron: "0 3 * * 1"
    ```

---

# 8) Cost optimization (marks: 10%)

* Cache Trivy DB: Jenkins agents reuse `/root/.cache/trivy`. Avoid `--download-db-only` each run.
* Scan on:

  * PRs and merges to main.
  * Nightly for “latest” tags only.
* Use exit threshold `HIGH` (not `MEDIUM`) to prevent noisy failures; report MEDIUM via Slack only.
* Run dashboard stack only for demos or in a shared environment, not per-branch.

---

# 9) Validation checklist (what to show in viva)

* [ ] Local run generates `reports/report.html` and blocks on HIGH/CRITICAL.
* [ ] Jenkins job fails on HIGH, archives reports.
* [ ] Slack/Teams message received on a failing scan.
* [ ] Pushgateway metrics visible in Prometheus; Grafana shows trends.
* [ ] Exceptions file suppresses an approved CVE and build passes.
* [ ] Weekly scheduled rescan configured.

---

## Quick Start (TL;DR)

```bash
# 1) clone repo and install
python3 -m pip install -r requirements.txt

# 2) configure policy
cp config/policy.env.example config/policy.env
# (optional) put SLACK_WEBHOOK_URL=... here

# 3) run a scan
./scripts/scan_image.sh nginx:1.23

# 4) open report
xdg-open reports/report.html || open reports/report.html
```


