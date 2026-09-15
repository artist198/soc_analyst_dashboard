# SOC Analyst Dashboard

A SOC (Security Operations Center) analyst dashboard built with **Streamlit + SQLite + Plotly**. Upload a security log — Windows `.evtx`, Linux/macOS syslog, JSON, CSV, or plain text — and the app normalizes it, runs detections, and drives every page from that data.

**Workflow:** Collect → Normalize → Detect → Correlate → Alert → Investigate → Incident → Respond → Report

Every page — Dashboard, Alerts, Incidents, Log Explorer, MITRE ATT&CK, Endpoint Monitoring, Network Monitoring, Reports, Audit Log — is generated from what you actually upload. Nothing is hardcoded demo data by default.

---

## Features

- **Multi-format log ingestion** — Windows `.evtx` (parsed natively with `wevtutil` on Windows), JSON/JSONL, CSV, and text/syslog/XML.
- **Automatic normalization** into one common log schema (timestamp, host, user, source/dest IP, port, severity, event).
- **Detection engine** that runs on every upload:
  - Known Windows Event ID patterns (failed logons, privilege use, new services, cleared audit logs, group changes).
  - Brute-force correlation (≥5 failed logins from the same source).
  - A generic catch-all that turns any HIGH/CRITICAL severity event into an alert, so unrecognized log types still surface.
- **Endpoint Monitoring** built automatically from the hosts/IPs seen in your uploads — not a static list.
- **Live monitoring** — `windows_collector.py --watch` continuously polls the live Windows Event Log and feeds the same pipeline, plus a **Live Mode** auto-refresh toggle in the dashboard sidebar.
- **Incident management**, MITRE ATT&CK coverage view, network/endpoint views, detection rule reference, CSV report exports, and a full audit trail.
- **Reset / Sample data controls** in the sidebar — start clean, or load example activity just to preview the UI.

---

## Screenshots

| | |
|---|---|
| ![Upload / Ingest Logs](screenshots/01-upload-ingest-logs.png) **Upload / Ingest Logs** — attach a log file and the parser normalizes + detects in one step. | ![Alert Investigation](screenshots/02-alert-investigation.png) **Alert Investigation** — severity, MITRE technique, host, and supporting evidence for each alert. |
| ![Incident Management](screenshots/03-incident-management.png) **Incident Management** — escalate an alert into a tracked incident with notes. | ![Log Explorer](screenshots/04-log-explorer.png) **Log Explorer** — filter and search every normalized event from your uploads. |
| ![MITRE ATT&CK Coverage](screenshots/05-mitre-attck-coverage.png) **MITRE ATT&CK Coverage** — which techniques your uploaded activity maps to. | ![Endpoint Monitoring](screenshots/06-endpoint-monitoring.png) **Endpoint Monitoring** — hosts discovered from uploaded logs, with live alert counts. |
| ![Network Monitoring](screenshots/07-network-monitoring.png) **Network Monitoring** — source/destination IP and port activity. | ![Detection Rules](screenshots/08-detection-rules.png) **Detection Rules** — the reference rule set the engine evaluates against. |
| ![Reports](screenshots/09-reports.png) **Reports** — alert/incident/upload counts with CSV export. | ![Audit Log](screenshots/10-audit-log.png) **Audit Log** — every ingest and analyst action, with a timestamp and result. |

---

## Installation (Windows)

### 1. Install Python

```powershell
py --version
```

If that fails, install Python from [python.org](https://www.python.org/) first (check "Add python.exe to PATH" during setup).

### 2. Get the project

Clone it if it's on GitHub:

```powershell
git clone https://github.com/yourname/soc-analyst-dashboard.git
cd soc-analyst-dashboard
```

...or just `cd` into the extracted `soc_fixed` folder if you downloaded a zip.

### 3. Create and activate a virtual environment

```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
```

If PowerShell blocks activation:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

### 4. Install dependencies

```powershell
py -m pip install -r requirements.txt
```

`pywin32` installs automatically — it's needed for native `.evtx` parsing and the live Windows Event Log collector.

### 5. (Optional) Configure email alerts

```powershell
copy .env.example .env
```

Fill in your SMTP details in `.env`. Without this, the app runs fine — email alerts just stay in demo mode.

### 6. Run the dashboard

```powershell
python -m streamlit run app.py
```

Open the URL it prints — usually `http://localhost:8501`.

---

## Using it

### Upload a log

Go to **Upload / Ingest Logs** → choose a file (`.evtx`, `.log`, `.txt`, `.json`, `.csv`, `.syslog`, `.xml`) → **Upload & Analyze**. The Dashboard, Alerts, Incidents, MITRE, Endpoint Monitoring, Network Monitoring, and Reports pages all update from that upload.

### Live / continuous monitoring

To feed the dashboard from the live Windows Event Log instead of manual exports, run (as Administrator):

```powershell
python windows_collector.py --log Security --watch --interval 15
```

It polls every 15 seconds, ingests only new events, and runs the full detection pipeline automatically. Turn on **🔴 Live Mode** in the dashboard sidebar so the page auto-refreshes and shows new activity as it comes in.

A one-shot pull also works if you don't need continuous monitoring:

```powershell
python windows_collector.py --log Security --max-events 200
```

### Start clean / preview with sample data

The sidebar has:
- **🧪 Load Sample Data** — populates the dashboard with example activity, for previewing the UI only.
- **🗑️ Reset All Data** — wipes alerts, logs, incidents, endpoints, and audit history so you can start fresh with real uploads.

---

## Supported Windows Event IDs

| Event ID | Meaning |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4648 | Explicit credential use |
| 4672 | Special privileges assigned |
| 4688 | Process creation |
| 4720 | User account created |
| 4728 / 4732 | Security group changes |
| 7045 | New service installed |
| 1102 | Security audit log cleared |

Any other event type is still ingested and shown in Log Explorer; it becomes an alert automatically if the parser tags it HIGH or CRITICAL severity.

---

## Safety

The Response Center is intentionally simulated — no live blocking/isolation actions are actually executed. Only connect automated response actions to systems you own or are explicitly authorized to monitor, and keep authentication, approval, audit logging, and least-privilege controls in place.

Only collect and upload logs from systems you are authorized to monitor.

## Notes

- The `.evtx` upload path uses Windows `wevtutil qe <file> /lf:true` — the `/lf:true` flag is required for archived (file-based) event logs; without it Windows returns "The specified channel path is invalid."
- SQLite database lives at `data/soc.db` and is git-ignored by default.

