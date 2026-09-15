"""Detections for normalized Windows Event Log data."""
from db import exec_sql, q


def _make_alert(source_ip, dest_ip, host, username, title, severity, mitre, description):
    exists = q("SELECT id FROM alerts WHERE host=? AND title=? AND status!='CLOSED' ORDER BY id DESC LIMIT 1", (host, title))
    if exists:
        return None
    return exec_sql(
        "INSERT INTO alerts(ts,severity,title,source_ip,dest_ip,host,username,mitre,status,analyst,description) VALUES(datetime('now'),?,?,?,?,?,?,?,?,?,?)",
        (severity, title, source_ip, dest_ip, host, username, mitre, "NEW", "Unassigned", description),
    )


def _mark_alerted(event_prefix: str):
    exec_sql("UPDATE logs SET alerted=1 WHERE event LIKE ?", (f"{event_prefix}%",))


def run_windows_detections():
    created = []
    # Brute force: >= 5 failed Windows logons per source IP.
    rows = q("""SELECT source_ip, host, COUNT(*) n FROM logs
                WHERE event LIKE 'Event ID 4625:%' AND source_ip NOT IN ('-', '')
                GROUP BY source_ip, host HAVING n>=5""")
    for r in rows:
        aid = _make_alert(r["source_ip"], r["host"], r["host"], "-", "Windows Brute Force Detected", "HIGH", "T1110", f"{r['n']} failed Windows logons from {r['source_ip']} against {r['host']}.")
        if aid: created.append(aid)
    _mark_alerted('Event ID 4625:')

    # Audit log cleared is critical.
    rows = q("SELECT host, username, source_ip FROM logs WHERE event LIKE 'Event ID 1102:%'")
    for r in rows:
        aid = _make_alert(r["source_ip"], r["host"], r["host"], r["username"], "Windows Security Log Cleared", "CRITICAL", "T1070.001", "Windows Security audit log was cleared; investigate immediately.")
        if aid: created.append(aid)
    _mark_alerted('Event ID 1102:')

    # New service installed.
    rows = q("SELECT host, username, source_ip FROM logs WHERE event LIKE 'Event ID 7045:%'")
    for r in rows:
        aid = _make_alert(r["source_ip"], r["host"], r["host"], r["username"], "New Windows Service Installed", "HIGH", "T1543.003", "A new Windows service installation was observed.")
        if aid: created.append(aid)
    _mark_alerted('Event ID 7045:')

    # Privileged local/global group additions.
    rows = q("SELECT host, username, source_ip, event FROM logs WHERE event LIKE 'Event ID 4732:%' OR event LIKE 'Event ID 4728:%'")
    for r in rows:
        aid = _make_alert(r["source_ip"], r["host"], r["host"], r["username"], "Windows Privileged Group Change", "HIGH", "T1098", "A user was added to a security-enabled Windows group.")
        if aid: created.append(aid)
    _mark_alerted('Event ID 4732:')
    _mark_alerted('Event ID 4728:')

    # Special privileges assigned - high severity, worth its own alert too.
    rows = q("SELECT host, username, source_ip FROM logs WHERE event LIKE 'Event ID 4672:%'")
    for r in rows:
        aid = _make_alert(r["source_ip"], r["host"], r["host"], r["username"], "Special Privileges Assigned", "HIGH", "T1078", "A logon was assigned special/administrative privileges.")
        if aid: created.append(aid)
    _mark_alerted('Event ID 4672:')

    return created
