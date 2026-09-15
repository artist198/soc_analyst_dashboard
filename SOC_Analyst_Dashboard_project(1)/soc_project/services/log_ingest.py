"""Cross-platform log ingestion helpers for the SOC dashboard.

Supports common SOC-friendly formats:
- Windows .evtx (native wevtutil on Windows; optional python-evtx fallback)
- JSON / JSON Lines
- CSV
- TXT / LOG / SYSLOG-style text

All formats are normalized into the dashboard's `logs` table.
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from db import exec_sql

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EVENT_ID_RE = re.compile(r"(?:Event\s*ID|EventID|event_id|id)\s*[:=]\s*(\d{3,6})", re.I)
SEVERITY_RE = re.compile(r"\b(CRITICAL|HIGH|MEDIUM|LOW|ERROR|WARNING|WARN|INFO|INFORMATION)\b", re.I)
TIME_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b")

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


def _valid_ip(value: Any) -> str:
    if not value:
        return "-"
    m = IP_RE.search(str(value))
    return m.group(0) if m else "-"


def _first(data: dict, names: list[str], default="-"):
    normalized = {re.sub(r"[^a-z0-9]", "", str(k).lower()): v for k, v in data.items()}
    for name in names:
        key = re.sub(r"[^a-z0-9]", "", name.lower())
        if key in normalized and normalized[key] not in (None, ""):
            return normalized[key]
    return default


def _severity(value: Any, event_id: int | None = None) -> str:
    if event_id in EVENT_MAP:
        return EVENT_MAP[event_id][1]
    s = str(value or "").upper()
    return {"ERROR": "HIGH", "WARNING": "MEDIUM", "WARN": "MEDIUM", "INFORMATION": "LOW", "INFO": "LOW"}.get(s, s if s in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "LOW")


def _mitre(event_id: int | None) -> str:
    return EVENT_MAP.get(event_id, ("", "LOW", ""))[2] if event_id else "-"


def _event_title(event_id: int | None, fallback: str) -> str:
    if event_id in EVENT_MAP:
        return EVENT_MAP[event_id][0]
    return fallback[:180] or "Uploaded Log Event"


def _timestamp(value: Any) -> str:
    if value in (None, ""):
        return datetime.now(timezone.utc).isoformat()
    text = str(value).strip()
    try:
        if text.endswith("Z"):
            return datetime.fromisoformat(text[:-1] + "+00:00").isoformat()
        return datetime.fromisoformat(text).isoformat()
    except Exception:
        return text[:80]


def _insert(row: dict) -> int:
    return exec_sql(
        "INSERT INTO logs(ts,source,host,username,event,source_ip,dest_ip,port,severity,raw) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (
            row.get("ts", datetime.now(timezone.utc).isoformat()), row.get("source", "Uploaded Log"),
            row.get("host", "-"), row.get("username", "-"), row.get("event", "Uploaded Log Event"),
            row.get("source_ip", "-"), row.get("dest_ip", "-"), int(row.get("port", 0) or 0),
            row.get("severity", "LOW"), row.get("raw", ""),
        ),
    )


def normalize_record(record: dict, source: str, os_type: str) -> dict:
    raw = json.dumps(record, ensure_ascii=False, default=str)[:10000]
    event_value = _first(record, ["event", "message", "description", "action", "event_name"], "Uploaded Log Event")
    eid_raw = _first(record, ["event_id", "eventid", "event.code", "event_code", "id"], "")
    try:
        eid = int(str(eid_raw).strip())
    except Exception:
        eid = None
    if eid:
        event = f"Event ID {eid}: {_event_title(eid, str(event_value))}"
    else:
        event = str(event_value)[:500]
    return {
        "ts": _timestamp(_first(record, ["timestamp", "time", "datetime", "date", "@timestamp"])),
        "source": f"Uploaded/{os_type}/{source}",
        "host": str(_first(record, ["host", "hostname", "computer", "computer_name", "device"])),
        "username": str(_first(record, ["username", "user", "user_name", "account", "subject_user_name"])),
        "event": event,
        "source_ip": _valid_ip(_first(record, ["source_ip", "src_ip", "src", "client_ip", "ip"])),
        "dest_ip": _valid_ip(_first(record, ["destination_ip", "dest_ip", "dst_ip", "dst", "server_ip"])),
        "port": _first(record, ["port", "destination_port", "dest_port"], 0),
        "severity": _severity(_first(record, ["severity", "level", "log_level", "type"]), eid),
        "raw": raw,
    }


def parse_json(text: str, source: str, os_type: str) -> list[dict]:
    records: list[Any] = []
    try:
        obj = json.loads(text)
        records = obj if isinstance(obj, list) else [obj]
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                records.append(obj)
            except Exception:
                continue
    return [normalize_record(r, source, os_type) for r in records if isinstance(r, dict)]


def parse_csv(text: str, source: str, os_type: str) -> list[dict]:
    reader = csv.DictReader(io.StringIO(text))
    return [normalize_record(dict(row), source, os_type) for row in reader]


def parse_text(text: str, source: str, os_type: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = EVENT_ID_RE.search(line)
        eid = int(m.group(1)) if m else None
        ips = IP_RE.findall(line)
        sev = SEVERITY_RE.search(line)
        rows.append({
            "ts": _timestamp(TIME_RE.search(line).group(1)) if TIME_RE.search(line) else datetime.now(timezone.utc).isoformat(),
            "source": f"Uploaded/{os_type}/{source}",
            "host": "-", "username": "-",
            "event": f"Event ID {eid}: {_event_title(eid, line)}" if eid else line[:500],
            "source_ip": _valid_ip(ips[0]) if ips else "-",
            "dest_ip": _valid_ip(ips[1]) if len(ips) > 1 else "-",
            "port": 0,
            "severity": _severity(sev.group(1) if sev else None, eid),
            "raw": line[:10000],
        })
    return rows


def _evtx_xml_on_windows(path: str) -> str:
    # Native Windows parser: no extra Python EVTX dependency required.
    # `wevtutil qe` normally treats its first argument as a live event-log
    # channel (for example, `Security`).  An uploaded `.evtx` is an archived
    # log file, so `/lf:true` is required; without it Windows reports:
    # "The specified channel path is invalid."
    result = subprocess.run(
        ["wevtutil", "qe", path, "/lf:true", "/f:xml"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "wevtutil could not read the EVTX file")
    return result.stdout


def parse_evtx(path: str, source: str, os_type: str) -> list[dict]:
    xml_text = ""
    if os.name == "nt":
        xml_text = _evtx_xml_on_windows(path)
    else:
        try:
            from Evtx.Evtx import Evtx  # optional python-evtx package
            from Evtx.Views import evtx_file_xml_view
            with Evtx(path) as log:
                xml_text = "\n".join(evtx_file_xml_view(log))
        except ImportError as exc:
            raise RuntimeError("Cross-platform EVTX parsing needs the optional 'python-evtx' package, or upload the EVTX on Windows.") from exc
    import xml.etree.ElementTree as ET
    rows = []
    # Handle multiple <Event> documents returned by wevtutil.
    for match in re.findall(r"<Event[\s\S]*?</Event>", xml_text, flags=re.I):
        try:
            root = ET.fromstring(match)
        except ET.ParseError:
            continue
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        system = root.find("e:System", ns)
        eid_el = system.find("e:EventID", ns) if system is not None else None
        eid = int(eid_el.text) if eid_el is not None and eid_el.text and eid_el.text.isdigit() else None
        provider = system.find("e:Provider", ns) if system is not None else None
        time_el = system.find("e:TimeCreated", ns) if system is not None else None
        host_el = system.find("e:Computer", ns) if system is not None else None
        data = {}
        for d in root.findall(".//e:EventData/e:Data", ns):
            if d.get("Name"):
                data[d.get("Name")] = d.text or ""
        username = data.get("TargetUserName") or data.get("SubjectUserName") or data.get("AccountName") or "-"
        source_ip = _valid_ip(data.get("IpAddress") or data.get("ClientAddress") or "-")
        row = {
            "ts": _timestamp(time_el.get("SystemTime") if time_el is not None else None),
            "source": f"Uploaded/{os_type}/{source}",
            "host": host_el.text if host_el is not None and host_el.text else "-",
            "username": username,
            "event": f"Event ID {eid}: {_event_title(eid, provider.get('Name','Windows Event') if provider is not None else 'Windows Event')}",
            "source_ip": source_ip,
            "dest_ip": "-", "port": 0,
            "severity": _severity(None, eid),
            "raw": ET.tostring(root, encoding="unicode")[:10000],
        }
        rows.append(row)
    return rows


def parse_uploaded_file(name: str, data: bytes, os_type: str = "Auto Detect") -> tuple[list[dict], str]:
    ext = Path(name).suffix.lower()
    if os_type == "Auto Detect":
        os_type = "Windows" if ext == ".evtx" else "Generic / Any OS"
    if ext == ".evtx":
        with tempfile.NamedTemporaryFile(delete=False, suffix=".evtx") as tmp:
            tmp.write(data); tmp_path = tmp.name
        try:
            rows = parse_evtx(tmp_path, Path(name).name, os_type)
        finally:
            try: os.unlink(tmp_path)
            except OSError: pass
    else:
        text = data.decode("utf-8", errors="replace")
        if ext == ".json": rows = parse_json(text, Path(name).name, os_type)
        elif ext == ".csv": rows = parse_csv(text, Path(name).name, os_type)
        elif ext in {".txt", ".log", ".syslog", ".xml"}: rows = parse_text(text, Path(name).name, os_type)
        else: raise ValueError(f"Unsupported file type: {ext or 'no extension'}")
    return rows, os_type


def ingest_rows(rows: list[dict]) -> int:
    count = 0
    for row in rows:
        _insert(row); count += 1
    return count
