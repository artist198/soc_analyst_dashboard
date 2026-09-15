# SOC Analyst Dashboard v2.0

A portfolio/college-level SOC dashboard built with **Streamlit + SQLite + Plotly**. The workflow is:

**Collect → Normalize → Detect → Correlate → Alert → Investigate → Incident → Respond → Report**

## What's new in v2.0

- Reference-style dark SOC dashboard with KPI cards, charts, alert tables, threat-intel panel and system status.
- **Created by Abhijith** branding tag in the header/sidebar/footer.
- Dedicated **Upload / Ingest Logs** section plus an upload/ingest panel on the main dashboard.
- Multi-file upload for Windows, Linux, macOS, BSD/Unix and generic log sources.
- Windows `.evtx` support using native `wevtutil` when the dashboard runs on Windows.
- JSON/JSONL, CSV, TXT/LOG/Syslog/XML text parsing.
- Normalization into a common `logs` schema.
- Automatic detection run after upload (generic brute-force + Windows detections).
- Ingestion batch history and audit trail.
- Existing alerts, incidents, MITRE ATT&CK, endpoint, network, response, reporting and email features retained.

## Run on Windows

```powershell
cd "C:\path\to\SOC_Analyst_Dashboard_Windows\soc_analyst_dashboard_pro"
py -m venv venv
.\venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
copy .env.example .env
python -m streamlit run app.py
```

For **Windows Security Event Log collection** from the live endpoint, open PowerShell as Administrator:

```powershell
python windows_collector.py --log Security --max-events 200
```

## Uploading an EVTX file

1. Open the dashboard.
2. Select **Upload / Ingest Logs** or use the dashboard's **Upload / Ingest Logs** panel.
3. Choose a `.evtx` file.
4. Leave **OS = Auto Detect** or choose **Windows**.
5. Click **Upload & Analyze**.
6. The dashboard normalizes supported Windows Event IDs and runs detection rules.

## Other OS logs

You can upload common `.log`, `.txt`, `.syslog`, `.json`, `.csv`, and text-based `.xml` logs. Choose the OS or leave Auto Detect. The parser extracts common fields such as timestamps, usernames, source/destination IPs, ports, event IDs and severity where available.

## Email alerts

Copy `.env.example` to `.env` and configure SMTP values. For Gmail, use an App Password rather than your normal password. Without SMTP configuration the app stays in demo mode.

## Safety

The response center is intentionally simulated. Only connect automated response actions to systems you own or are explicitly authorized to monitor, and keep authentication, approval, audit logging and least-privilege controls in place.

### EVTX upload note

The dashboard uses Windows `wevtutil` with `/lf:true` when parsing an uploaded `.evtx` archive. This is required for file-based event logs; using `wevtutil qe <file>` without `/lf:true` causes the Windows error `The specified channel path is invalid.`
