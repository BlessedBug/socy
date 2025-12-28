import osimport os
import json
import time
import smtplib
import shutil
import joblib
import pandas as pd
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import google.generativeai as genai
import tempfile

WATCH_DIR = "/home/ubuntu/files"
STATE_DIR = "/home/ubuntu/state"
PAYLOAD_DIR = "/home/ubuntu/payloads"
PROC_DIR = "/home/ubuntu/proc"
PROCESSED_DB = f"{STATE_DIR}/processed.json"
PROCESSED_ARCHIVE = "/home/ubuntu/pfiles"
ML_STATE_DIR = "/home/ubuntu/state/ml_analyzed"

RF_CONFIDENCE_THRESHOLD = 85.0
START_HOUR = 8
END_HOUR = 17

SUPERVISED_MODEL = "/home/ubuntu/socy/supervised_model.pkl"
UNSUPERVISED_MODEL = "/home/ubuntu/socy/unsupervised_model.pkl"

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_EMAIL = os.environ.get("SMTP_EMAIL")
SMTP_PASS = os.environ.get("SMTP_PASSWORD")

ADMIN_EMAIL = [
    "shehriyaraslam2.0@gmail.com",
    "ammarcyber.s@gmail.com"
]

GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY")
genai.configure(api_key=GOOGLE_API_KEY)

AI_MODELS = ["gemini-1.5-flash", "gemini-1.5-pro"]

os.makedirs(STATE_DIR, exist_ok=True)
os.makedirs(PAYLOAD_DIR, exist_ok=True)
os.makedirs(PROC_DIR, exist_ok=True)
os.makedirs(PROCESSED_ARCHIVE, exist_ok=True)
os.makedirs(ML_STATE_DIR, exist_ok=True)

processed = set()
if os.path.exists(PROCESSED_DB):
    try:
        processed = set(json.load(open(PROCESSED_DB)))
    except:
        processed = set()

NUM_COLS = ["cpu_pct", "mem_mb", "child_count", "remote_port", "sent_mb", "recv_mb"]
TEXT_COLS = ["proc_name", "path", "source", "event_type", "username", "remote_ip", "device"]

def atomic_save_state():
    fd, tmp = tempfile.mkstemp(dir=STATE_DIR)
    with os.fdopen(fd, "w") as f:
        json.dump(list(processed), f)
    os.replace(tmp, PROCESSED_DB)

def is_file_stable(path, wait=2):
    try:
        s1 = os.path.getsize(path)
        time.sleep(wait)
        s2 = os.path.getsize(path)
        return s1 == s2
    except:
        return False

def list_pending_files():
    if not os.path.exists(WATCH_DIR):
        return []
    out = []
    for f in os.listdir(WATCH_DIR):
        if not f.endswith(".csv") and not f.endswith(".log"):
            continue
        if f in processed:
            continue
        fp = os.path.join(WATCH_DIR, f)
        if is_file_stable(fp):
            out.append(fp)
    return out

def safe(p, i, d=""):
    try:
        return p[i].strip()
    except:
        return d

def to_float(x):
    try:
        cleaned = str(x).lower().replace("sent:","").replace("recv:","").replace("mb","").replace("%","").replace("file_path:","").strip()
        if ":" in cleaned:
            cleaned = cleaned.split(":")[-1]
        return float(cleaned)
    except:
        return 0.0

def parse_line(line):
    if not line.strip():
        return {c:0.0 for c in NUM_COLS} | {c:"" for c in TEXT_COLS}

    p = line.strip().split(",")
    r = {c:0.0 for c in NUM_COLS}
    r.update({c:"" for c in TEXT_COLS})

    r["timestamp"] = safe(p, 0)
    r["log_level"] = safe(p, 1)
    r["username"] = safe(p, 2)

    raw_upper = line.upper()

    if "USB_DEVICE" in raw_upper or "USBSTOR" in raw_upper:
        r["source"] = "usb"
        r["event_type"] = safe(p, 4)
        r["device"] = safe(p, 5)
        r["path"] = safe(p, 6)
        return r

    if "NETWORK" in raw_upper or (len(p) > 8 and "." in safe(p, 8)):
        r["source"] = "network"
        r["proc_name"] = safe(p, 4)
        r["pid"] = safe(p, 5)
        r["remote_ip"] = safe(p, 8)
        r["sent_mb"] = to_float(safe(p, 9))
        r["recv_mb"] = to_float(safe(p, 10))
        r["event_type"] = "NET_CONNECT"
        return r

    if "PROCESS" in raw_upper or "SUBPROCESS" in raw_upper:
        r["source"] = "process"
        r["proc_name"] = safe(p, 4)
        r["pid"] = safe(p, 5)
        r["mem_mb"] = to_float(safe(p, 6))
        r["cpu_pct"] = to_float(safe(p, 7))
        r["child_count"] = to_float(safe(p, 8))
        r["path"] = safe(p, 9)
        r["event_type"] = safe(p, 10)
        return r

    if "AUTH" in raw_upper or "LOGON" in raw_upper:
        r["source"] = "auth"
        r["event_id"] = safe(p, 4)
        r["event_type"] = safe(p, 5)
        r["username"] = safe(p, 6)
        r["path"] = safe(p, 7)
        return r

    if "ACCESS" in raw_upper or "FILE_MODIFIED" in raw_upper:
        r["source"] = "access"
        r["event_type"] = safe(p, 4)
        r["path"] = safe(p, 5).replace("file_path:","").strip()
        return r

    r["source"] = safe(p, 3).lower()
    return r

def load_csv(fp):
    rows = []
    with open(fp, errors="ignore") as f:
        for line in f:
            r = parse_line(line)
            r["raw"] = line.strip()
            rows.append(r)
    return pd.DataFrame(rows)

def ai_analyze(threats):
    prompt = json.dumps(threats, indent=2)
    for m in AI_MODELS:
        try:
            model = genai.GenerativeModel(m)
            r = model.generate_content(prompt)
            if r and r.text:
                return r.text.strip()
        except:
            continue
    return "USB activity confirmed malicious. Immediate containment required."

def send_email(payload):
    msg = MIMEMultipart()
    msg["From"] = SMTP_EMAIL
    msg["To"] = ", ".join(ADMIN_EMAIL)
    msg["Subject"] = f"SOC ALERT [{payload['severity']}]"
    msg.attach(MIMEText(json.dumps(payload, indent=2), "plain"))
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as s:
        s.login(SMTP_EMAIL, SMTP_PASS)
        s.send_message(msg)

def main():
    try:
        rf = joblib.load(SUPERVISED_MODEL)
        iso = joblib.load(UNSUPERVISED_MODEL)
    except:
        rf = None
        iso = None

    for fp in list_pending_files():
        fname = os.path.basename(fp)
        df = load_csv(fp)

        if df.empty:
            processed.add(fname)
            atomic_save_state()
            shutil.move(fp, os.path.join(PROCESSED_ARCHIVE, fname))
            continue

        threats = []
        reasons = set()
        affected_ips = set()

        for _, row in df.iterrows():
            row_reasons = []

            if row["source"] == "usb":
                row_reasons.append("USB_MALICIOUS")

            try:
                h = datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S").hour
                if not (START_HOUR <= h < END_HOUR):
                    row_reasons.append("OFFTIME")
            except:
                pass

            if row["remote_ip"]:
                affected_ips.add(row["remote_ip"])

            if row_reasons:
                reasons.update(row_reasons)
                threats.append(row.to_dict())

                if row["source"] == "usb":
                    payload = {
                        "generated_at": datetime.utcnow().isoformat(),
                        "source_file": fname,
                        "severity": "CRITICAL",
                        "reasons": list(reasons),
                        "analysis": "USB activity detected. Classified as malicious by policy.",
                        "response": "Isolate host immediately and block USB access"
                    }
                    name = f"payload_{fname.replace('.csv','')}.json"
                    for d in [PAYLOAD_DIR, PROC_DIR]:
                        with open(os.path.join(d, name), "w") as f:
                            json.dump(payload, f, indent=2)
                    send_email(payload)

        if threats:
            pd.DataFrame(threats).to_csv(os.path.join(PROC_DIR, f"threat_{fname}"), index=False)

        processed.add(fname)
        atomic_save_state()
        shutil.move(fp, os.path.join(PROCESSED_ARCHIVE, fname))

if __name__ == "__main__":
    main()


