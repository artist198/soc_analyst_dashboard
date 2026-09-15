from db import q, exec_sql


def correlate_bruteforce():
    """SSH-style brute force: >=5 failed logins from the same source IP."""
    rows = q("""SELECT source_ip, COUNT(*) n FROM logs
                WHERE (event LIKE '%SSH failed login%' OR event LIKE '%failed login%')
                  AND source_ip NOT IN ('-','')
                GROUP BY source_ip HAVING n>=5""")
    created = []
    for r in rows:
        exists = q("SELECT id FROM alerts WHERE source_ip=? AND title='SSH Brute Force Detected' AND status!='CLOSED'", (r['source_ip'],))
        if not exists:
            aid = exec_sql(
                "INSERT INTO alerts(ts,severity,title,source_ip,dest_ip,host,username,mitre,status,analyst,description) VALUES(datetime('now'),'HIGH','SSH Brute Force Detected',?,?,?,?, 'T1110','NEW','Unassigned',?)",
                (r['source_ip'], '-', '-', '-', f'{r["n"]} failed SSH logins correlated by source IP.'),
            )
            created.append(aid)
    return created


def run_generic_detections():
    """Catch-all for uploaded logs that don't match a specific known Windows
    Event ID pattern (see services/windows_detection.py) or the brute-force
    correlation above. Any log row tagged HIGH or CRITICAL severity by the
    parser is surfaced as an alert, so the Dashboard/Alerts/Incidents/MITRE/
    Reports pages always reflect what was actually uploaded - not just a
    handful of hardcoded event types.

    Each log row is only ever considered once (tracked via logs.alerted) so
    re-running the detection engine doesn't create duplicate alerts.
    """
    rows = q("""SELECT id, ts, source, host, username, event, source_ip, dest_ip, severity
                FROM logs WHERE alerted=0 AND severity IN ('HIGH','CRITICAL')""")
    created = []
    for r in rows:
        aid = exec_sql(
            "INSERT INTO alerts(ts,severity,title,source_ip,dest_ip,host,username,mitre,status,analyst,description) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                r['ts'], r['severity'], r['event'][:180] or 'Uploaded Log Event',
                r['source_ip'] or '-', r['dest_ip'] or '-', r['host'] or '-', r['username'] or '-',
                '-', 'NEW', 'Unassigned',
                f"Flagged from uploaded log ({r['source']}): {r['event']}",
            ),
        )
        created.append(aid)
    if rows:
        exec_sql(f"UPDATE logs SET alerted=1 WHERE id IN ({','.join('?' * len(rows))})", tuple(r['id'] for r in rows))
    return created
