import sqlite3, os, random
from datetime import datetime, timedelta

DB = 'data/soc.db'
os.makedirs('data', exist_ok=True)


def conn():
    c = sqlite3.connect(DB, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def _add_column_if_missing(cur, table, column, coltype):
    cols = [r[1] for r in cur.execute(f'PRAGMA table_info({table})').fetchall()]
    if column not in cols:
        cur.execute(f'ALTER TABLE {table} ADD COLUMN {column} {coltype}')


def init_db():
    c = conn(); cur = c.cursor()
    cur.executescript('''
    CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, severity TEXT, title TEXT, source_ip TEXT, dest_ip TEXT, host TEXT, username TEXT, mitre TEXT, status TEXT, analyst TEXT, description TEXT);
    CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT, title TEXT, severity TEXT, host TEXT, source_ip TEXT, status TEXT, analyst TEXT, mitre TEXT, notes TEXT);
    CREATE TABLE IF NOT EXISTS logs(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, source TEXT, host TEXT, username TEXT, event TEXT, source_ip TEXT, dest_ip TEXT, port INTEGER, severity TEXT, raw TEXT);
    CREATE TABLE IF NOT EXISTS endpoints(id INTEGER PRIMARY KEY AUTOINCREMENT, hostname TEXT UNIQUE, ip TEXT, os TEXT, status TEXT, cpu REAL, ram REAL, last_seen TEXT, alerts INTEGER);
    CREATE TABLE IF NOT EXISTS rules(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, threshold TEXT, severity TEXT, mitre TEXT, enabled INTEGER);
    CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor TEXT, action TEXT, target TEXT, result TEXT);
    CREATE TABLE IF NOT EXISTS ingest_batches(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, filename TEXT, os_type TEXT, format TEXT, events INTEGER, status TEXT);
    CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
    ''')
    # Migration: older databases (created by earlier app versions) won't have
    # this column yet. It lets the detection engine mark which uploaded log
    # rows it has already evaluated, so generic detections don't re-fire on
    # the same event every time the engine runs.
    _add_column_if_missing(cur, 'logs', 'alerted', 'INTEGER DEFAULT 0')
    c.commit()

    # Detection Rules is a reference/config table (not sample activity) -
    # it should always be populated so the "Detection Rules" page isn't empty,
    # regardless of whether the user has uploaded any logs yet.
    if cur.execute('SELECT COUNT(*) FROM rules').fetchone()[0] == 0:
        seed_rules(c)

    # NOTE: alerts / logs / endpoints are intentionally left empty on first
    # run. Every one of those tables is meant to reflect what the analyst
    # has actually uploaded - nothing is auto-populated with sample data
    # anymore. Use load_demo_data() explicitly (there's a sidebar button for
    # it) if you want to see the dashboard populated with example activity.
    c.close()


def seed_rules(c):
    rules = [
        ('Windows Brute Force', '>=5 Event ID 4625 / source', 'HIGH', 'T1110', 1),
        ('Suspicious PowerShell', 'PowerShell encoded/suspicious command', 'HIGH', 'T1059.001', 1),
        ('Port Scan', '>20 ports / 2 min', 'HIGH', 'T1046', 1),
        ('New Admin Account', 'new privileged user', 'MEDIUM', 'T1098', 1),
        ('Security Log Cleared', 'Event ID 1102', 'CRITICAL', 'T1070.001', 1),
        ('Rare DNS', 'domain rarity score > 0.9', 'LOW', 'T1071.004', 1),
        ('High/Critical Severity Event', 'Any ingested log tagged HIGH or CRITICAL', 'HIGH', 'T1059', 1),
    ]
    for r in rules:
        c.execute('INSERT INTO rules(name,threshold,severity,mitre,enabled) VALUES(?,?,?,?,?)', r)
    c.commit()


def is_real_data_present() -> bool:
    c = conn(); cur = c.cursor()
    n = cur.execute('SELECT COUNT(*) FROM logs').fetchone()[0]
    c.close()
    return n > 0


def reset_all_data():
    """Wipe everything derived from uploads/demo data so the dashboard goes
    back to a clean, empty state. Detection rule definitions are kept since
    they're configuration, not activity data."""
    c = conn(); cur = c.cursor()
    for table in ('alerts', 'incidents', 'logs', 'endpoints', 'ingest_batches', 'audit'):
        cur.execute(f'DELETE FROM {table}')
        cur.execute('DELETE FROM sqlite_sequence WHERE name=?', (table,))
    cur.execute("DELETE FROM meta WHERE key='demo_loaded'")
    c.commit(); c.close()


def sync_endpoint(hostname: str, ip: str, os_type: str):
    """Upsert an endpoint row from data actually seen in an uploaded log,
    instead of relying on a static hardcoded endpoint list."""
    if not hostname or hostname == '-':
        return
    c = conn(); cur = c.cursor()
    now = datetime.now().isoformat(timespec='seconds')
    existing = cur.execute('SELECT id, ip FROM endpoints WHERE hostname=?', (hostname,)).fetchone()
    alert_count = cur.execute('SELECT COUNT(*) FROM alerts WHERE host=?', (hostname,)).fetchone()[0]
    if existing:
        cur.execute(
            'UPDATE endpoints SET ip=?, os=?, status=?, last_seen=?, alerts=? WHERE hostname=?',
            (ip if ip and ip != '-' else existing['ip'], os_type, 'ONLINE', now, alert_count, hostname),
        )
    else:
        cur.execute(
            'INSERT INTO endpoints(hostname,ip,os,status,cpu,ram,last_seen,alerts) VALUES(?,?,?,?,?,?,?,?)',
            (hostname, ip or '-', os_type, 'ONLINE', 0, 0, now, alert_count),
        )
    c.commit(); c.close()


def load_demo_data():
    """Optional: explicitly populate the dashboard with sample activity so a
    brand-new install has something to look at. Never called automatically."""
    c = conn(); cur = c.cursor()
    if cur.execute('SELECT COUNT(*) FROM alerts').fetchone()[0] > 0 or cur.execute('SELECT COUNT(*) FROM logs').fetchone()[0] > 0:
        c.close()
        return False
    _seed_demo(c)
    cur.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('demo_loaded','1')")
    c.commit(); c.close()
    return True


def _seed_demo(c):
    now = datetime.now()
    targets = [('192.0.2.10', 28), ('198.51.100.23', 21), ('203.0.113.50', 15), ('45.33.32.156', 12), ('103.21.244.8', 9), ('185.12.44.8', 8), ('10.0.0.44', 7), ('10.0.0.55', 6), ('10.0.0.72', 5), ('10.0.0.91', 4), ('10.0.0.99', 3), ('10.0.0.101', 2), ('10.0.0.111', 2), ('10.0.0.120', 1), ('10.0.0.121', 1)]
    ips = []
    for ip, n in targets: ips.extend([ip] * n)
    random.seed(42); random.shuffle(ips)
    sevs = ['CRITICAL'] * 18 + ['HIGH'] * 42 + ['MEDIUM'] * 36 + ['LOW'] * 28
    random.shuffle(sevs)
    types = ['Brute Force'] * 42 + ['IOC Detection'] * 28 + ['Suspicious Login'] * 18 + ['Malware Activity'] * 12 + ['Other'] * 24
    random.shuffle(types)
    mitre_map = {'Brute Force': 'T1110', 'IOC Detection': 'T1568', 'Suspicious Login': 'T1078', 'Malware Activity': 'T1204', 'Other': 'T1059'}
    for idx in range(124):
        sev = sevs[idx]; typ = types[idx]; ip = ips[idx] if idx < len(ips) else f'10.0.0.{idx+2}'
        host = ['WIN-CLIENT-07', 'WIN-SRV-01', 'WIN-SRV-02', 'WIN-CLIENT-03', 'WEB-SERVER-01'][idx % 5]
        user = ['admin', 'administrator', 'jsmith', '-'][idx % 4]
        status = ['NEW', 'NEW', 'ACKNOWLEDGED', 'INVESTIGATING', 'NEW'][idx % 5]
        c.execute('INSERT INTO alerts(ts,severity,title,source_ip,dest_ip,host,username,mitre,status,analyst,description) VALUES(?,?,?,?,?,?,?,?,?,?,?)', ((now - timedelta(minutes=idx * 9)).isoformat(timespec='seconds'), sev, typ, ip, '10.0.0.10', host, user, mitre_map[typ], status, 'A. Analyst' if status != 'NEW' else 'Unassigned', f'{typ} detected by the SOC detection pipeline. (Sample data)'))
    for i in range(300):
        sev = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'][i % 4]
        typ = ['SSH failed login', 'Windows Event ID 4625', 'Windows Event ID 4688', 'Outbound connection', 'IOC match', 'PowerShell activity'][i % 6]
        ip = ips[i % len(ips)]
        host = ['WIN-CLIENT-07', 'WIN-SRV-01', 'WIN-SRV-02', 'WEB-SERVER-01'][i % 4]
        c.execute('INSERT INTO logs(ts,source,host,username,event,source_ip,dest_ip,port,severity,raw,alerted) VALUES(?,?,?,?,?,?,?,?,?,?,?)', ((now - timedelta(minutes=i * 4)).isoformat(timespec='seconds'), 'demo/windows' if 'Windows' in typ or 'PowerShell' in typ else 'demo/network', host, 'admin' if i % 3 == 0 else 'jsmith', typ, ip, '10.0.0.10', 22 if i % 5 == 0 else 443, sev, 'SAMPLE DATA - not from an uploaded log', 1))
    eps = [('WIN-SRV-01', '10.0.0.10', 'Windows Server 2022', 'ONLINE', 34, 61), ('WIN-SRV-02', '10.0.0.20', 'Windows Server 2022', 'ONLINE', 27, 48), ('WIN-CLIENT-07', '10.0.0.55', 'Windows 11', 'ALERT', 76, 83), ('WIN-CLIENT-03', '10.0.0.72', 'Windows 11', 'ONLINE', 41, 59), ('WEB-SERVER-01', '10.0.0.91', 'Ubuntu 24.04', 'ONLINE', 28, 52), ('PC-104', '10.0.0.104', 'Windows 10', 'OFFLINE', 0, 0)]
    for idx, (h, ip, os_, st, cpu, ram) in enumerate(eps):
        c.execute('INSERT INTO endpoints(hostname,ip,os,status,cpu,ram,last_seen,alerts) VALUES(?,?,?,?,?,?,?,?)', (h, ip, os_, st, cpu, ram, now.isoformat(timespec='seconds'), (idx + 2) % 9 + 1))
    c.commit()


def get_meta(key: str, default=None):
    c = conn(); row = c.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone(); c.close()
    return row['value'] if row else default


def set_meta(key: str, value: str):
    c = conn(); c.execute('INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)', (key, str(value))); c.commit(); c.close()


def q_with_cols(sql, params=()):
    c = conn(); cur = c.execute(sql, params); rows = cur.fetchall()
    cols = [d[0] for d in cur.description] if cur.description else []
    c.close()
    return rows, cols


def q(sql, params=()):
    c = conn(); rows = c.execute(sql, params).fetchall(); c.close(); return rows


def exec_sql(sql, params=()):
    c = conn(); cur = c.execute(sql, params); c.commit(); rid = cur.lastrowid; c.close(); return rid
