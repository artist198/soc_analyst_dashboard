"""Windows Event Log collector for the SOC dashboard.
Run this script on an authorized Windows endpoint as Administrator.
It reads events straight from the live Windows Event Log (Security/System/
Application) and writes normalized rows into the same SQLite database the
Streamlit dashboard reads from - so it behaves exactly like an upload, just
sourced from the live log instead of an exported .evtx file.

One-shot pull (grabs the most recent N events once):
    python windows_collector.py --log Security --max-events 200

Continuous live monitoring (recommended - keeps running, only ingests events
it hasn't seen before, and re-runs the detection engine after every batch so
Dashboard / Alerts / Incidents / Endpoint Monitoring stay current):
    python windows_collector.py --log Security --watch --interval 15
"""
import argparse
import socket
import time
from datetime import datetime, timezone

from db import exec_sql, init_db, get_meta, set_meta, sync_endpoint
from services.detection_engine import correlate_bruteforce, run_generic_detections
from services.windows_detection import run_windows_detections

EVENT_MAP = {
    4624: ("Successful Windows Logon", "LOW", "T1078"),
    4625: ("Windows Failed Logon", "MEDIUM", "T1110"),
    4648: ("Explicit Credential Use", "MEDIUM", "T1078"),
    4672: ("Special Privileges Assigned", "HIGH", "T1078"),
    4688: ("Windows Process Creation", "LOW", "T1059"),
    4720: ("Windows User Account Created", "MEDIUM", "T1136"),
    4728: ("User Added to Global Security Group", "HIGH", "T1098"),
    4732: ("User Added to Local Security Group", "HIGH", "T1098"),
    7045: ("New Windows Service Installed", "HIGH", "T1543.003"),
    1102: ("Windows Security Audit Log Cleared", "CRITICAL", "T1070.001"),
}


def _event_fields(event):
    strings = list(event.StringInserts or [])
    user = strings[1] if len(strings) > 1 else "-"
    source_ip = "-"
    for value in strings:
        if isinstance(value, str) and value.count(".") == 3:
            parts = value.split(".")
            if all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                source_ip = value
                break
    return user, source_ip


def _bookmark_key(log_name: str) -> str:
    return f"collector_bookmark_{log_name}"


def collect(log_name="Security", max_events=100, since_record=0):
    """Read the most recent events from a live Windows Event Log channel.
    Only events with RecordNumber > since_record are ingested, and the
    highest RecordNumber seen is returned so the caller can bookmark it -
    this is what makes --watch mode idempotent (no duplicate rows on
    repeated polls)."""
    try:
        import win32evtlog
    except ImportError as exc:
        raise SystemExit("pywin32 is required. Run: py -m pip install pywin32") from exc

    server = "localhost"
    handle = win32evtlog.OpenEventLog(server, log_name)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events = []
    max_record_seen = since_record
    scanned = 0
    host = socket.gethostname()
    try:
        while scanned < max(max_events, 1000):
            batch = win32evtlog.ReadEventLog(handle, flags, 0)
            if not batch:
                break
            hit_bookmark = False
            for event in batch:
                scanned += 1
                record_no = int(event.RecordNumber)
                if record_no <= since_record:
                    hit_bookmark = True
                    break
                max_record_seen = max(max_record_seen, record_no)
                eid = int(event.EventID) & 0xFFFF
                if eid not in EVENT_MAP:
                    continue
                title, severity, mitre = EVENT_MAP[eid]
                username, source_ip = _event_fields(event)
                ts = datetime.fromtimestamp(event.TimeGenerated.timestamp(), tz=timezone.utc).isoformat()
                raw = f"provider={event.SourceName};event_id={eid};record={record_no};strings={list(event.StringInserts or [])}"
                exec_sql(
                    "INSERT INTO logs(ts,source,host,username,event,source_ip,dest_ip,port,severity,raw) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (ts, f"Live/Windows Event Log/{log_name}", host, username, f"Event ID {eid}: {title}", source_ip, host, 0, severity, raw),
                )
                events.append({"host": host, "source_ip": source_ip})
                if len(events) >= max_events:
                    hit_bookmark = True
                    break
            if hit_bookmark:
                break
    finally:
        win32evtlog.CloseEventLog(handle)
    return events, max_record_seen


def run_pipeline(events):
    """Mirror what the dashboard's Upload & Analyze button does: run every
    detection pass, then refresh Endpoint Monitoring for hosts we just saw."""
    ids = []
    try: ids += run_windows_detections()
    except Exception: pass
    try: ids += correlate_bruteforce()
    except Exception: pass
    try: ids += run_generic_detections()
    except Exception: pass
    for host_ip in {(e["host"], e["source_ip"]) for e in events}:
        sync_endpoint(host_ip[0], host_ip[1], "Windows")
    return ids


def main():
    parser = argparse.ArgumentParser(description="Collect Windows Event Logs into the SOC dashboard database")
    parser.add_argument("--log", default="Security", choices=["Security", "System", "Application"], help="Windows Event Log channel")
    parser.add_argument("--max-events", type=int, default=100, help="Max events to pull per poll")
    parser.add_argument("--watch", action="store_true", help="Keep running and poll continuously instead of exiting after one pull")
    parser.add_argument("--interval", type=int, default=15, help="Seconds between polls in --watch mode")
    args = parser.parse_args()
    init_db()

    bookmark_key = _bookmark_key(args.log)
    since_record = int(get_meta(bookmark_key, 0) or 0)

    if not args.watch:
        events, max_record = collect(args.log, args.max_events, since_record)
        set_meta(bookmark_key, max_record)
        ids = run_pipeline(events) if events else []
        print(f"Collected {len(events)} new mapped Windows events from {args.log}; {len(ids)} alert(s) created.")
        return

    print(f"Live-monitoring '{args.log}' every {args.interval}s. Press Ctrl+C to stop.")
    while True:
        try:
            events, max_record = collect(args.log, args.max_events, since_record)
            if events:
                since_record = max_record
                set_meta(bookmark_key, since_record)
                ids = run_pipeline(events)
                print(f"[{datetime.now().strftime('%H:%M:%S')}] {len(events)} new event(s) ingested, {len(ids)} alert(s) created.")
            time.sleep(args.interval)
        except KeyboardInterrupt:
            print("Stopped.")
            break


if __name__ == "__main__":
    main()
