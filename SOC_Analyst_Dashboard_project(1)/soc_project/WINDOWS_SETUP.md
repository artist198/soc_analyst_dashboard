# Windows Setup — SOC Analyst Dashboard v2.0

## 1. Install Python

Use a supported Python release and verify:

```powershell
py --version
```

## 2. Create and activate the environment

```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
```

If PowerShell blocks activation:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

## 3. Install packages

```powershell
py -m pip install -r requirements.txt
```

The Windows build installs `pywin32` automatically because it is a Windows-only dependency.

## 4. Start the dashboard

```powershell
python -m streamlit run app.py
```

Open the displayed `http://localhost:8501` address.

## 5. Collect live Windows Security events

One-shot pull (grabs recent events once), run PowerShell as Administrator:

```powershell
python windows_collector.py --log Security --max-events 200
```

You can also collect System or Application logs:

```powershell
python windows_collector.py --log System --max-events 200
python windows_collector.py --log Application --max-events 200
```

### Continuous / active monitoring

To keep the dashboard live instead of pulling once, use `--watch`. This polls
the event log on an interval, ingests only events it hasn't seen before
(tracked via a bookmark in the database), and runs the full detection engine
after every batch - so Dashboard, Alerts, Incidents, MITRE ATT&CK, and
Endpoint Monitoring all update automatically as new events occur:

```powershell
python windows_collector.py --log Security --watch --interval 15
```

Leave this running in its own terminal window (or set it up as a Scheduled
Task / background service so it survives logoff). In the Streamlit dashboard,
turn on **🔴 Live Mode** in the sidebar so the page auto-refreshes and shows
what the collector is writing without a manual reload.

## 6. Upload an exported Windows Event Log

In Event Viewer (`eventvwr.msc`), right-click a log such as **Security** → **Save All Events As...** and save an `.evtx` file. In the dashboard, use **Upload / Ingest Logs → Upload & Analyze**.

When the dashboard itself runs on Windows, `.evtx` is parsed with the built-in `wevtutil` command, so no third-party EVTX parser is required.

## Supported Windows Event IDs

- 4624 — Successful logon
- 4625 — Failed logon
- 4648 — Explicit credential use
- 4672 — Special privileges assigned
- 4688 — Process creation
- 4720 — User account created
- 4728 / 4732 — Security group changes
- 7045 — New service installed
- 1102 — Security audit log cleared

Only collect systems and logs you are authorized to monitor.

### EVTX upload note

The dashboard uses Windows `wevtutil` with `/lf:true` when parsing an uploaded `.evtx` archive. This is required for file-based event logs; using `wevtutil qe <file>` without `/lf:true` causes the Windows error `The specified channel path is invalid.`
