import os, smtplib
from email.message import EmailMessage
from dotenv import load_dotenv
load_dotenv()

def send_alert(subject, body):
    host=os.getenv('SMTP_HOST'); port=int(os.getenv('SMTP_PORT','587')); user=os.getenv('SMTP_USER'); pwd=os.getenv('SMTP_PASSWORD'); recipient=os.getenv('ALERT_RECIPIENT')
    if not all([host,user,pwd,recipient]): return False, 'SMTP not configured; running in demo mode.'
    msg=EmailMessage(); msg['Subject']=subject; msg['From']=user; msg['To']=recipient; msg.set_content(body)
    with smtplib.SMTP(host,port,timeout=15) as s:
        s.starttls(); s.login(user,pwd); s.send_message(msg)
    return True, 'Email sent.'
