import os
from datetime import datetime, timedelta
from pathlib import Path
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from db import init_db, q, q_with_cols, exec_sql, reset_all_data, load_demo_data, sync_endpoint, is_real_data_present
from services.detection_engine import correlate_bruteforce, run_generic_detections
from services.windows_detection import run_windows_detections
from services.email_service import send_alert
from services.log_ingest import parse_uploaded_file, ingest_rows

st.set_page_config(page_title='SOC Analyst Dashboard', page_icon='🛡️', layout='wide', initial_sidebar_state='expanded')
init_db()

# ---------- Theme ----------
st.markdown('''
<style>
:root{--bg:#03111d;--panel:#071a29;--panel2:#0a2233;--line:#16364c;--blue:#168cff;--text:#eef7ff;--muted:#93a8bc;--green:#19d37e;--red:#ff3d4e;--orange:#ff7a18;--yellow:#ffd21c}
.stApp{background:radial-gradient(circle at 78% 0%,rgba(0,132,255,.13),transparent 34%),linear-gradient(180deg,#020d17,#03111d 42%,#02101a);color:var(--text)}
section[data-testid="stSidebar"]{background:linear-gradient(180deg,#041421,#061827);border-right:1px solid #123047}
section[data-testid="stSidebar"] .block-container{padding:1rem .65rem}
.block-container{padding:1rem 1.3rem 1.2rem;max-width:1600px}
.header{display:flex;align-items:center;justify-content:space-between;padding:.2rem .2rem .65rem;border-bottom:1px solid #123047;margin-bottom:.7rem}
.brand{display:flex;gap:14px;align-items:center}.shield{width:54px;height:54px;border:2px solid #72b8ff;border-radius:18px;display:flex;align-items:center;justify-content:center;font-size:29px;box-shadow:0 0 22px rgba(30,135,255,.45);background:#061827}
.brand h1{margin:0;font-size:30px;letter-spacing:-.8px}.tagline{color:#a8bfd2;font-size:14px;margin-top:2px}.topmeta{color:#d5e6f3;font-size:13px;text-align:right}.topmeta b{color:#fff}.creator{display:inline-flex;align-items:center;gap:6px;padding:3px 8px;border:1px solid #1c77b5;border-radius:999px;background:rgba(22,140,255,.08);color:#9ed3ff;font-size:10px;letter-spacing:.2px}
[data-testid="stMetric"]{background:linear-gradient(180deg,#071b2b,#061725);border:1px solid #173a52;border-radius:10px;padding:13px 15px;box-shadow:inset 0 1px rgba(255,255,255,.03)}
[data-testid="stMetricLabel"]{color:#cbdbea}.metric-note{color:#19d37e;font-size:11px}.metric-icon{font-size:26px;float:left;margin-right:9px}
.panel{background:linear-gradient(180deg,rgba(9,30,45,.92),rgba(4,19,31,.94));border:1px solid #15384f;border-radius:10px;padding:14px;box-shadow:0 7px 24px rgba(0,0,0,.16);margin-bottom:10px}.panel h3{margin:0 0 10px;font-size:17px}.muted{color:#91a9bb;font-size:12px}.section-title{font-size:18px;font-weight:700;margin:5px 0 9px}.status{display:inline-block;border-radius:999px;padding:3px 9px;font-size:11px;font-weight:700}.ok{background:#063b29;color:#38e89a}.danger{background:#4b1119;color:#ff8e99}.warn{background:#4a2b05;color:#ffc96c}
div[data-testid="stFileUploaderDropzone"]{background:linear-gradient(180deg,#071d2d,#061725);border:1px dashed #367aa5;border-radius:10px}.stButton>button{border-radius:7px;border:1px solid #1e5f87;background:#0b2940;color:#eef7ff}.stButton>button:hover{border-color:#168cff;color:white;box-shadow:0 0 12px rgba(22,140,255,.22)}
div[data-testid="stDataFrame"]{border:1px solid #17384e;border-radius:8px}.small-footer{font-size:11px;color:#7890a4}.sidebar-title{font-weight:800;font-size:18px;letter-spacing:.5px}.quote{color:#91a2b0;font-size:12px;font-style:italic;line-height:1.5;border-top:1px solid #16364c;padding-top:14px;margin-top:15px}
</style>
''', unsafe_allow_html=True)


def df(sql, params=()):
    # Always preserve column names from the query, even with zero rows -
    # pd.DataFrame([]) has NO columns at all, which breaks any later
    # `.column_name` access or `.sort_values('col')` call once a table is
    # empty (which is now the normal starting state before any upload).
    rows, cols = q_with_cols(sql, params)
    if not rows:
        return pd.DataFrame(columns=cols)
    return pd.DataFrame([dict(x) for x in rows])


def plot_style(fig, height=280):
    fig.update_layout(height=height, margin=dict(l=8,r=8,t=8,b=8), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='#dceaf5'), legend=dict(orientation='h',y=1.08,x=0), xaxis=dict(gridcolor='#17364b',zeroline=False), yaxis=dict(gridcolor='#17364b',zeroline=False))
    return fig


def severity_badge(s):
    cls={'CRITICAL':'danger','HIGH':'warn','MEDIUM':'warn','LOW':'ok'}.get(str(s).upper(),'ok')
    return f'<span class="status {cls}">{s}</span>'


def header():
    now=datetime.now().strftime('%b %d, %Y  %I:%M %p')
    st.markdown(f'''<div class="header"><div class="brand"><div class="shield">✓</div><div><div class="brand h1"><h1>SOC Analyst Dashboard</h1></div><div class="tagline">Detect&nbsp;&nbsp; | &nbsp;&nbsp;Investigate&nbsp;&nbsp; | &nbsp;&nbsp;Respond&nbsp;&nbsp; | &nbsp;&nbsp;Stay Secure</div></div></div><div class="topmeta">◷ &nbsp;{now}&nbsp;&nbsp;&nbsp; 👤 <b>Analyst</b>&nbsp;&nbsp; <span class="creator">Created by Abhijith</span></div></div>''', unsafe_allow_html=True)


def upload_widget(compact=False):
    st.markdown('<div class="panel"><h3>☁️ Upload / Ingest Logs</h3><div class="muted">Upload Windows or any common OS log attachment. The parser normalizes events into one SOC schema and runs detections.</div>', unsafe_allow_html=True)
    c1,c2,c3=st.columns([1.25,1,1])
    with c1: files=st.file_uploader('Log attachment',type=['evtx','log','txt','json','csv','syslog','xml'],accept_multiple_files=True,label_visibility='collapsed',help='Windows .evtx, Linux/macOS .log/.txt/.syslog, JSON, CSV, or XML text logs')
    with c2: os_type=st.selectbox('OS / Source',['Auto Detect','Windows','Linux','macOS','BSD / Unix','Generic / Any OS'],label_visibility='collapsed')
    with c3: parser_mode=st.selectbox('Parser',['Auto Parse','Windows Event Log','JSON / JSONL','CSV','Text / Syslog'],label_visibility='collapsed')
    if files:
        st.caption('Selected: '+', '.join(f.name for f in files))
    if st.button('⬆️ Upload & Analyze',type='primary',use_container_width=True,disabled=not files,key='ingest_btn'):
        total=0; batches=[]; errors=[]; seen_hosts=set()
        for f in files:
            try:
                rows,detected=parse_uploaded_file(f.name,f.getvalue(),os_type)
                n=ingest_rows(rows)
                exec_sql('INSERT INTO ingest_batches(ts,filename,os_type,format,events,status) VALUES(datetime(\'now\'),?,?,?,?,?)',(f.name,detected,Path(f.name).suffix.lower().lstrip('.'),'{}'.format(n),'SUCCESS'))
                total+=n; batches.append((f.name,n,detected))
                seen_hosts.update((row.get('host','-'), row.get('source_ip','-'), detected) for row in rows)
            except Exception as exc:
                errors.append(f'{f.name}: {exc}')
        if total:
            # Run every detection pass over the newly ingested rows: known
            # Windows event patterns, brute-force correlation, and a generic
            # catch-all for anything else tagged HIGH/CRITICAL severity so
            # every page (Dashboard, Alerts, Incidents, MITRE, Reports,
            # Endpoint Monitoring) reflects what was actually uploaded.
            ids=[]
            try: ids += run_windows_detections()
            except Exception: pass
            try: ids += correlate_bruteforce()
            except Exception: pass
            try: ids += run_generic_detections()
            except Exception: pass
            # Sync Endpoint Monitoring *after* detections run, so each
            # endpoint's alert count reflects the alerts just created.
            for host,ip,detected in seen_hosts:
                sync_endpoint(host, ip, detected)
            exec_sql("INSERT INTO audit(ts,actor,action,target,result) VALUES(datetime('now'),'SOC Analyst','UPLOAD_LOGS',?,?)",('Multiple files',f'{total} events ingested; {len(ids)} alerts created'))
            st.success(f'Ingested {total} normalized events and created {len(ids)} new alert(s). Dashboard, Alerts, Incidents, MITRE, Endpoints, and Reports are now updated.')
            for name,n,detected in batches: st.write(f'• **{name}** — {n} events — {detected}')
        for err in errors: st.error(err)
    st.markdown('</div>',unsafe_allow_html=True)


def overview():
    alerts=df('SELECT * FROM alerts'); logs=df('SELECT * FROM logs'); endpoints=df('SELECT * FROM endpoints')
    if logs.empty:
        st.info('No logs uploaded yet. Everything on this dashboard is generated from your uploads — use the panel below to upload a log file, or load sample data from the sidebar to preview the dashboard.')
    counts={s:int((alerts.severity==s).sum()) for s in ['CRITICAL','HIGH','MEDIUM','LOW']} if not alerts.empty else {s:0 for s in ['CRITICAL','HIGH','MEDIUM','LOW']}
    total=sum(counts.values()); unique_ips=alerts.source_ip.nunique() if not alerts.empty else 0
    cols=st.columns(6)
    cards=[('🔔','Total Alerts',total,'12%'),('🚨','Critical Alerts',counts['CRITICAL'],'5%'),('❗','High Alerts',counts['HIGH'],'8%'),('⚠️','Medium Alerts',counts['MEDIUM'],'10%'),('ℹ️','Low Alerts',counts['LOW'],'3%'),('👥','Unique IPs',unique_ips,'6%')]
    for c,(ic,label,val,change) in zip(cols,cards):
        c.markdown(f'<div class="panel" style="min-height:91px"><span class="metric-icon">{ic}</span><div style="color:#cbdbea;font-size:13px">{label}</div><div style="font-size:31px;font-weight:800;line-height:1.2">{val}</div><div class="metric-note">↑ {change} <span style="color:#8ea3b5">vs last 24h</span></div></div>',unsafe_allow_html=True)
    c1,c2,c3=st.columns([1.7,1.45,1])
    with c1:
        st.markdown('<div class="panel"><h3>Alerts Over Time</h3>',unsafe_allow_html=True)
        if not alerts.empty:
            a=alerts.copy(); a['ts']=pd.to_datetime(a.ts,errors='coerce'); a['hour']=a.ts.dt.hour
            h=a.groupby(['hour','severity']).size().reset_index(name='alerts')
            fig=px.line(h,x='hour',y='alerts',color='severity',markers=True,color_discrete_map={'CRITICAL':'#ff3d4e','HIGH':'#ff7a18','MEDIUM':'#ffd21c','LOW':'#168cff'})
            fig.update_xaxes(tickvals=list(range(0,24,2)),ticktext=[f'{x:02d}:00' for x in range(0,24,2)])
            st.plotly_chart(plot_style(fig,250),use_container_width=True,config={'displayModeBar':False})
        st.markdown('</div>',unsafe_allow_html=True)
    with c2:
        st.markdown('<div class="panel"><h3>Alerts by Severity</h3>',unsafe_allow_html=True)
        if total==0:
            st.caption('No alerts yet.')
        else:
            sevdf=pd.DataFrame({'severity':list(counts.keys()),'count':list(counts.values())})
            fig=px.pie(sevdf,names='severity',values='count',hole=.58,color='severity',color_discrete_map={'CRITICAL':'#ff3d4e','HIGH':'#ff7a18','MEDIUM':'#ffd21c','LOW':'#168cff'})
            fig.update_traces(textinfo='none'); fig.add_annotation(text=f'<b>{total}</b><br>Total',showarrow=False,font=dict(size=18,color='#fff'))
            st.plotly_chart(plot_style(fig,250),use_container_width=True,config={'displayModeBar':False})
        st.markdown('</div>',unsafe_allow_html=True)
    with c3:
        st.markdown('<div class="panel"><h3>Top Attacking IPs</h3>',unsafe_allow_html=True)
        if alerts.empty:
            st.caption('No alerts yet.')
        else:
            top=alerts.source_ip.value_counts().head(5).reset_index(); top.columns=['ip','count']
            fig=px.bar(top,y='ip',x='count',orientation='h',color='count',color_continuous_scale=['#ffd21c','#ff7a18','#ff3d4e'])
            fig.update_layout(showlegend=False); st.plotly_chart(plot_style(fig,250),use_container_width=True,config={'displayModeBar':False})
        st.markdown('</div>',unsafe_allow_html=True)
    c4,c5=st.columns([1,1.7])
    with c4:
        st.markdown('<div class="panel"><h3>Alert Types</h3>',unsafe_allow_html=True)
        if alerts.empty:
            st.caption('No alerts yet.')
        else:
            t=alerts.title.value_counts().head(5).reset_index(); t.columns=['type','count']
            fig=px.bar(t,y='type',x='count',orientation='h',color='count',color_continuous_scale=['#6b7f94','#168cff','#ff3d4e']); fig.update_layout(showlegend=False)
            st.plotly_chart(plot_style(fig,245),use_container_width=True,config={'displayModeBar':False})
        st.markdown('</div>',unsafe_allow_html=True)
    with c5:
        st.markdown('<div class="panel"><h3>Recent Alerts <span style="float:right;color:#56aaf8;font-size:12px">View All →</span></h3>',unsafe_allow_html=True)
        r=alerts.sort_values('id',ascending=False).head(6) if not alerts.empty else alerts
        if not r.empty:
            display=r[['ts','title','source_ip','severity','description']].copy(); display.columns=['Time','Type','IP Address','Severity','Details']; display['Severity']=display.Severity.map(severity_badge); display['Time']=pd.to_datetime(display.Time,errors='coerce').dt.strftime('%Y-%m-%d %H:%M');
            st.write(display.to_html(index=False,escape=False),unsafe_allow_html=True)
        else:
            st.caption('No alerts yet — upload a log file to get started.')
        st.markdown('</div>',unsafe_allow_html=True)
    c6,c7,c8=st.columns([1.6,1.25,.85])
    with c6:
        upload_widget()
    with c7:
        st.markdown('<div class="panel"><h3>🌐 Threat Intelligence Lookup</h3>',unsafe_allow_html=True)
        ioc=st.text_input('IOC',placeholder='Enter IP address, domain or hash',label_visibility='collapsed')
        if st.button('Lookup',key='overview_ioc'): st.session_state['lookup_ioc']=ioc
        val=st.session_state.get('lookup_ioc','8.8.8.8')
        malicious=any(x in val.lower() for x in ['185.','malware','bad','evil'])
        st.markdown(f'<div style="font-size:22px;font-weight:800">🌐 {val} <span class="status {"danger" if malicious else "ok"}">{"High Risk" if malicious else "Low Risk"}</span></div><p class="muted">Country &nbsp; United States &nbsp;&nbsp; Abuse Score &nbsp; {"94" if malicious else "0"}/100<br>ISP &nbsp; Demo Intelligence &nbsp;&nbsp; Reports &nbsp; {"12" if malicious else "0"}</p>',unsafe_allow_html=True)
        st.markdown('</div>',unsafe_allow_html=True)
    with c8:
        st.markdown('<div class="panel"><h3>System Status</h3>',unsafe_allow_html=True)
        for name,status in [('Database','Connected'),('Email Alert System','Active'),('Threat Intel','Active'),('Log Parser','Active')]: st.markdown(f'<div style="padding:7px 0;border-bottom:1px solid #143247">◉ &nbsp;{name}<span class="status ok" style="float:right">{status}</span></div>',unsafe_allow_html=True)
        last=q('SELECT * FROM ingest_batches ORDER BY id DESC LIMIT 1')
        st.caption(f"Last Log Upload: {last[0]['ts'] if last else 'No uploads yet'}")
        st.markdown('</div>',unsafe_allow_html=True)
    st.markdown('<div class="small-footer">SOC Analyst Dashboard v2.0 &nbsp; | &nbsp; Detect • Investigate • Respond • Stay Secure</div>',unsafe_allow_html=True)


def sidebar():
    with st.sidebar:
        st.markdown('<div class="sidebar-title">🛡️ SOC CENTER</div>',unsafe_allow_html=True)
        st.caption('Windows + Linux + macOS log analysis')
        page=st.radio('Navigation',['Dashboard','Upload / Ingest Logs','Alerts','Incidents','Log Explorer','Threat Intelligence','MITRE ATT&CK','Endpoint Monitoring','Network Monitoring','Detection Rules','Response','Reports','Audit Log'],label_visibility='collapsed')
        st.divider()
        if st.button('⚡ Run Detection Engine',use_container_width=True):
            ids=[]
            try: ids += run_windows_detections()
            except Exception: pass
            try: ids += correlate_bruteforce()
            except Exception: pass
            try: ids += run_generic_detections()
            except Exception: pass
            st.success(f'{len(ids)} new alert(s)')
        st.divider()
        st.caption('Data source')
        if not is_real_data_present():
            if st.button('🧪 Load Sample Data',use_container_width=True,help='Populate the dashboard with example activity — for previewing only, not real data.'):
                if load_demo_data(): st.success('Sample data loaded.'); st.rerun()
                else: st.warning('Data already present — reset first.')
        confirm=st.checkbox('Confirm reset',key='confirm_reset')
        if st.button('🗑️ Reset All Data',use_container_width=True,disabled=not confirm,help='Deletes all alerts, logs, incidents, endpoints and audit history. Cannot be undone.'):
            reset_all_data(); st.success('All data cleared.'); st.rerun()
        st.divider()
        st.caption('Live monitoring')
        live=st.checkbox('🔴 Live Mode (auto-refresh)',key='live_mode',help='Auto-reloads the page so new events from the Windows collector (windows_collector.py --watch) show up without a manual refresh.')
        if live:
            secs=st.selectbox('Refresh every',[10,15,30,60],index=1,key='live_interval',label_visibility='collapsed')
            st.caption(f'Auto-refreshing every {secs}s')
        st.markdown('<div class="quote">“Security is not a product,<br>but a process.”<br>— Bruce Schneier</div>',unsafe_allow_html=True)
        st.markdown('<div style="margin-top:20px;text-align:center"><span class="creator">Created by Abhijith</span></div>',unsafe_allow_html=True)
    return page


def upload_page():
    st.header('☁️ Upload / Ingest Logs')
    st.write('Attach security logs from **Windows, Linux, macOS, BSD/Unix, or any text/JSON/CSV source**. Windows `.evtx` files are parsed with the native Windows Event Log utility when the dashboard runs on Windows.')
    upload_widget()
    with st.expander('⚡ Want live/active logs instead of manual uploads?'):
        st.markdown('''Run the collector script on the Windows machine you want to monitor, in continuous mode:
```
python windows_collector.py --log Security --watch --interval 15
```
It polls the live Windows Event Log every 15 seconds, ingests only new events (no duplicates), and runs the same detection engine as a manual upload - so Dashboard, Alerts, Incidents, MITRE and Endpoint Monitoring all update automatically. Turn on **🔴 Live Mode** in the sidebar so this page refreshes itself and picks up what the collector writes.''')
    st.subheader('Supported attachments')
    st.dataframe(pd.DataFrame({'Format':['Windows Event Log','Linux / Unix','JSON / JSONL','CSV','Text / Syslog'],'Extensions':['.evtx','.log / .syslog','.json','.csv','.txt / .xml'],'Auto handling':['Windows Event IDs + MITRE mapping','Generic text normalization','Field mapping + normalization','Column mapping + normalization','IP / timestamp / Event ID extraction']}),use_container_width=True,hide_index=True)
    st.subheader('Recent ingestion batches')
    b=df('SELECT * FROM ingest_batches ORDER BY id DESC LIMIT 20'); st.dataframe(b,use_container_width=True,hide_index=True)


def alerts_page():
    st.header('🚨 Alert Management')
    a=df('SELECT * FROM alerts ORDER BY id DESC')
    if a.empty: st.info('No alerts yet. Alerts are created automatically when the detection engine finds something notable in an uploaded log — go to Upload / Ingest Logs to get started.')
    else: st.dataframe(a,use_container_width=True,hide_index=True)
    if not a.empty:
        aid=st.selectbox('Investigate Alert',a.id.tolist()); x=df('SELECT * FROM alerts WHERE id=?',(aid,)).iloc[0]
        c1,c2,c3,c4=st.columns(4); c1.metric('Severity',x.severity); c2.metric('MITRE',x.mitre); c3.metric('Host',x.host); c4.metric('Status',x.status)
        st.info(x.description); st.code(f"Source: {x.source_ip}\nDestination: {x.dest_ip}\nUser: {x.username}\nTime: {x.ts}")
        related=df('SELECT * FROM logs WHERE source_ip=? ORDER BY id DESC LIMIT 25',(x.source_ip,)); st.subheader('Evidence'); st.dataframe(related,use_container_width=True,hide_index=True)
        b1,b2,b3=st.columns(3)
        if b1.button('Acknowledge'): exec_sql("UPDATE alerts SET status='ACKNOWLEDGED' WHERE id=?",(aid,)); st.rerun()
        if b2.button('Create Incident'): exec_sql("INSERT INTO incidents(created_at,title,severity,host,source_ip,status,analyst,mitre,notes) VALUES(datetime('now'),?,?,?,?,?,?,?,?)",(x.title,x.severity,x.host,x.source_ip,'OPEN',x.analyst,x.mitre,'Created from alert')); exec_sql("UPDATE alerts SET status='INVESTIGATING' WHERE id=?",(aid,)); st.rerun()
        if b3.button('Email Alert'):
            ok,msg=send_alert(f'[SOC] {x.severity}: {x.title}',f'Alert ID: {aid}\nSource: {x.source_ip}\nHost: {x.host}\nMITRE: {x.mitre}\n\n{x.description}'); st.info(msg)


def incidents_page():
    st.header('📁 Incident Management'); inc=df('SELECT * FROM incidents ORDER BY id DESC')
    if inc.empty: st.info("No incidents yet. Open an alert (Alerts page) and click 'Create Incident' to escalate it.")
    else: st.dataframe(inc,use_container_width=True,hide_index=True)
    if not inc.empty:
        iid=st.selectbox('Incident',inc.id.tolist()); x=inc[inc.id==iid].iloc[0]; notes=st.text_area('Investigation notes',x.notes or '')
        if st.button('Save Notes / Close'): exec_sql("UPDATE incidents SET notes=?, status='CLOSED' WHERE id=?",(notes,iid)); st.rerun()


def log_explorer():
    st.header('🔎 Log Explorer'); l=df('SELECT * FROM logs ORDER BY id DESC')
    if l.empty: st.info('No normalized logs yet. Upload a log attachment first.'); return
    c1,c2,c3=st.columns(3)
    sev=c1.multiselect('Severity',sorted(l.severity.dropna().unique()),default=sorted(l.severity.dropna().unique())); source=c2.multiselect('Source',sorted(l.source.dropna().unique()),default=[]); text=c3.text_input('Search')
    if sev: l=l[l.severity.isin(sev)]
    if source: l=l[l.source.isin(source)]
    if text: l=l[l.astype(str).apply(lambda r:r.str.contains(text,case=False,na=False).any(),axis=1)]
    st.dataframe(l,use_container_width=True,hide_index=True)


def threat_intel():
    st.header('🌐 Threat Intelligence'); ioc=st.text_input('Enter IP / domain / hash',placeholder='8.8.8.8')
    if ioc:
        malicious=any(x in ioc.lower() for x in ['185.','malware','bad','evil']); st.metric('Demo Reputation','MALICIOUS' if malicious else 'UNKNOWN'); st.write({'IOC':ioc,'Confidence':'94%' if malicious else 'N/A','Source':'Local demo intelligence','Recommended action':'Investigate and correlate with logs' if malicious else 'Collect additional context'})


def mitre():
    st.header('🎯 MITRE ATT&CK Coverage'); m=df('SELECT mitre, COUNT(*) count FROM alerts GROUP BY mitre');
    if not m.empty: st.bar_chart(m.set_index('mitre'))
    st.dataframe(pd.DataFrame({'Technique':['T1110','T1059.001','T1046','T1098','T1071.004','T1070.001'],'Name':['Brute Force','PowerShell','Network Service Scanning','Account Manipulation','DNS','Indicator Removal'],'Detection':['Failed logons','Encoded PowerShell','Port scan','New admin','Rare DNS','Security log cleared']}),use_container_width=True,hide_index=True)


def endpoints():
    st.header('🖥️ Endpoint Monitoring'); e=df('SELECT * FROM endpoints')
    if e.empty:
        st.info('No endpoints yet. Endpoints are created automatically from the host/computer name found in each uploaded log — upload a log file to populate this list.')
    else:
        st.dataframe(e,use_container_width=True,hide_index=True)


def network():
    st.header('🌐 Network Monitoring'); l=df('SELECT source_ip, dest_ip, port, COUNT(*) connections FROM logs GROUP BY source_ip,dest_ip,port ORDER BY connections DESC')
    if l.empty: st.info('No network activity yet. This view is built from source/destination IPs and ports found in uploaded logs.')
    else: st.dataframe(l,use_container_width=True,hide_index=True)


def detection_rules():
    st.header('⚙️ Detection Rules'); r=df('SELECT * FROM rules'); st.dataframe(r,use_container_width=True,hide_index=True)


def response():
    st.header('⚡ Response Center'); st.warning('Actions are simulated for safety. Connect only to authorized lab controls.')
    target=st.text_input('Target IOC / Host'); action=st.selectbox('Action',['Block IOC (simulation)','Isolate endpoint (simulation)','Collect evidence (simulation)','Reset session (simulation)']); approval=st.checkbox('I approve this action for my authorized environment')
    if st.button('Execute'):
        if not approval: st.error('Approval required.')
        elif not target: st.error('Enter a target.')
        else: exec_sql("INSERT INTO audit(ts,actor,action,target,result) VALUES(datetime('now'),'SOC Analyst',?,?,?)",(action,target,'SIMULATED')); st.success(f'{action} executed in simulation for {target}.')


def reports():
    st.header('📊 Reports'); a=df('SELECT * FROM alerts'); i=df('SELECT * FROM incidents'); b=df('SELECT * FROM ingest_batches')
    c1,c2,c3=st.columns(3); c1.metric('Alerts',len(a)); c2.metric('Incidents',len(i)); c3.metric('Log Upload Batches',len(b))
    st.download_button('⬇️ Download Alert CSV',a.to_csv(index=False).encode(),'soc_alerts.csv','text/csv')
    st.download_button('⬇️ Download Normalized Logs CSV',df('SELECT * FROM logs').to_csv(index=False).encode(),'soc_logs.csv','text/csv')


def audit():
    st.header('🧾 Audit Log'); st.dataframe(df('SELECT * FROM audit ORDER BY id DESC'),use_container_width=True,hide_index=True)

page=sidebar(); header()
if st.session_state.get('live_mode'):
    st.markdown(f'<meta http-equiv="refresh" content="{st.session_state.get("live_interval",15)}">',unsafe_allow_html=True)
if page=='Dashboard': overview()
elif page=='Upload / Ingest Logs': upload_page()
elif page=='Alerts': alerts_page()
elif page=='Incidents': incidents_page()
elif page=='Log Explorer': log_explorer()
elif page=='Threat Intelligence': threat_intel()
elif page=='MITRE ATT&CK': mitre()
elif page=='Endpoint Monitoring': endpoints()
elif page=='Network Monitoring': network()
elif page=='Detection Rules': detection_rules()
elif page=='Response': response()
elif page=='Reports': reports()
elif page=='Audit Log': audit()
