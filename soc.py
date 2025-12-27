import os
import json
import time
import smtplib
import shutil
import joblib
import pandas as pd
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from google import genai

WATCH_DIR = r"/home/ubuntu/files"
STATE_DIR = r"/home/ubuntu/state"
PAYLOAD_DIR = r"/home/ubuntu/payloads"
PROCESSED_DB = f"{STATE_DIR}/processed.json"
PROCESSED_ARCHIVE = r"/home/ubuntu/pfiles"
ML_STATE_DIR = r"/home/ubuntu/state/ml_analyzed"

RF_CONFIDENCE_THRESHOLD = 85.0
CPU_ABUSE = 90.0
MEM_ABUSE_MB = 4096

START_HOUR = 8
END_HOUR = 17

SUPERVISED_MODEL = r"/home/ubuntu/socy/supervised_model.pkl"
UNSUPERVISED_MODEL = r"/home/ubuntu/socy/unsupervised_model.pkl"

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_EMAIL = os.environ.get("SMTP_EMAIL")
SMTP_PASS = os.environ.get("SMTP_PASSWORD")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL")

GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY")
client = genai.Client(api_key=GOOGLE_API_KEY)

os.makedirs(STATE_DIR, exist_ok=True)
os.makedirs(PAYLOAD_DIR, exist_ok=True)
os.makedirs(PROCESSED_ARCHIVE, exist_ok=True)
os.makedirs(ML_STATE_DIR, exist_ok=True)

if os.path.exists(PROCESSED_DB):
    try:
        processed = set(json.load(open(PROCESSED_DB)))
    except:
        processed = set()
else:
    processed = set()

NUM_COLS = ["cpu_pct", "mem_mb", "child_count", "remote_port", "sent_mb", "recv_mb"]
TEXT_COLS = ["proc_name", "path", "source", "event_type", "username", "remote_ip", "device"]

def save_state():
    json.dump(list(processed), open(PROCESSED_DB, "w"))

def is_file_stable(path, wait_seconds=2):
    try:
        size1 = os.path.getsize(path)
        time.sleep(wait_seconds)
        size2 = os.path.getsize(path)
        return size1 == size2
    except:
        return False

def list_pending_files():
    files = []
    if not os.path.exists(WATCH_DIR): return []
    for f in os.listdir(WATCH_DIR):
        if not f.endswith(".csv") and not f.endswith(".log"):
            continue
        full = os.path.join(WATCH_DIR, f)
        if f in processed:
            continue
        if not is_file_stable(full):
            continue
        files.append(full)
    return files

def safe(p, i, default=""):
    try:
        return p[i].strip()
    except:
        return default

def to_float(x):
    try:
        cleaned = str(x).lower().replace("sent:","").replace("recv:","").replace("mb","").replace("%","").replace("file_path:","").strip()
        if ":" in cleaned: cleaned = cleaned.split(":")[-1]
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

def ai_confirm(row):
    prompt = f"""
You are a senior Windows SOC malware analyst and EDR decision engine.
You are analyzing raw Windows endpoint telemetry. Data may be partial or incomplete.
LOG ENTRY:
{json.dumps(row, indent=2)}
EDR CONTEXT:
- Process creation and termination events
- Parent-child process relationships
- File creation, modification, deletion
- Registry modifications (run keys, services, scheduled tasks)
- Network connections (IP, domain, port, protocol)
- Authentication and logon activity
- USB and removable media activity
- CPU, RAM, and disk usage
- Code-signing status and image execution paths
ANALYSIS RULES (STRICT — NO EXCEPTIONS):
- USB insertion or removable media execution is ALWAYS malicious
- Ignore signed Microsoft and Windows system or kernel binaries UNLESS:
  - Executed from non-standard or user-writable paths
  - Spawned by non-system or suspicious parent processes
  - Performing persistence, credential access, or abnormal network activity
- High CPU, RAM, or disk usage alone is NOT malicious and must NOT trigger detection
- Living-off-the-land binaries (PowerShell, cmd, wmic, rundll32, mshta, certutil) are benign by default and suspicious ONLY if:
  - Command-line obfuscation is present
  - External payloads are downloaded
  - Security controls are modified or disabled
- Strong malicious indicators include:
  - Persistence mechanisms (registry run keys, services, scheduled tasks)
  - Credential access, LSASS interaction, or token manipulation
  - Process injection, hollowing, or memory tampering
  - Unsigned binaries executing from user-writable directories
- Network activity is suspicious ONLY if:
  - External, unknown, or hard-coded endpoints are contacted
  - Abnormal ports or protocols are used
  - Encrypted payloads are transmitted without legitimate business justification
- Correlate behavior across process, file, registry, and network events
- Validate actions against normal enterprise and administrative behavior
- Do NOT infer intent based on process names, file names, or reputation alone
- If events do NOT form a coherent malicious behavior chain, downgrade severity
- If evidence is ambiguous, incomplete, or explainable, classify as FALSE_POSITIVE
- Zero tolerance for assumptions or speculation
ANSWER STRICTLY IN THIS FORMAT (NO EXTRA TEXT):
VERDICT: REAL_THREAT or VERDICT: FALSE_POSITIVE
REASON: Concise technical justification referencing observed EDR signals
"""
    try:
        r = client.models.generate_content(model="gemini-2.0-flash", contents=[prompt])
        return r.candidates[0].content.parts[0].text.strip()
    except Exception as e:
        return f"VERDICT: REAL_THREAT\nREASON: AI analysis failed: {e}"

def send_email(payload):
    msg = MIMEMultipart()
    msg["From"] = SMTP_EMAIL
    msg["To"] = ADMIN_EMAIL
    msg["Subject"] = f"SOC ALERT [{payload['severity']}] {payload['threat_type']}"
    msg.attach(MIMEText(json.dumps(payload, indent=2), "plain"))
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as s:
        s.login(SMTP_EMAIL, SMTP_PASS)
        s.send_message(msg)

def move_to_archive(src_path):
    base = os.path.basename(src_path)
    dst = os.path.join(PROCESSED_ARCHIVE, base)
    try:
        shutil.move(src_path, dst)
    except:
        if os.path.exists(src_path): os.remove(src_path)

def main():
    try:
        rf = joblib.load(SUPERVISED_MODEL)
        iso = joblib.load(UNSUPERVISED_MODEL)
    except Exception as e:
        print(f"[FATAL] Failed to load ML models: {e}")
        return

    files = list_pending_files()
    if not files: return

    for fp in files:
        fname = os.path.basename(fp)
        df = load_csv(fp)
        if df.empty:
            processed.add(fname); save_state(); move_to_archive(fp)
            continue

        used_ml = False
        for i, row in df.iterrows():
            triggers = []
            
            try:
                ts_obj = datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
                if not (START_HOUR <= ts_obj.hour < END_HOUR):
                    triggers.append(f"After-hours activity ({ts_obj.hour}:00)")
            except:
                pass
            
            if row["source"] == "usb":
                triggers.append("USB insertion detected")
            
            if row["cpu_pct"] >= CPU_ABUSE or row["mem_mb"] >= MEM_ABUSE_MB:
                triggers.append("Resource abuse")

            if row["source"] in ["process", "network"]:
                used_ml = True
                try:
                    input_data = df.loc[[i], NUM_COLS]
                    rf_p = rf.predict(input_data)[0]
                    rf_conf = max(rf.predict_proba(input_data)[0]) * 100
                    iso_p = iso.predict(input_data)[0]

                    if rf_p == 1 and rf_conf > RF_CONFIDENCE_THRESHOLD:
                        triggers.append(f"RandomForest ({round(rf_conf,2)}%)")
                    if iso_p == -1:
                        triggers.append("IsolationForest Anomaly")
                except:
                    pass

            if not triggers:
                continue

            verdict = ai_confirm(row.to_dict())
            if "FALSE_POSITIVE" in verdict.upper():
                continue

            payload = {
                "platform": "windows",
                "generated_at": datetime.utcnow().isoformat(),
                "source_file": fname,
                "severity": "CRITICAL",
                "threat_type": row["source"],
                "user": row["username"],
                "process": row.get("proc_name", ""),
                "device": row.get("device", ""),
                "confidence_sources": triggers,
                "analysis": verdict,
                "response_plan": {
                    "kill_process": row.get("proc_name", ""), 
                    "block_network": True,
                    "lock_system": True
                }
            }

            out = f"{PAYLOAD_DIR}/payload_{int(time.time())}_{i}.json"
            with open(out, "w") as f: json.dump(payload, f, indent=2)
            try:
                send_email(payload)
            except:
                pass

        if used_ml:
            ml_log_path = os.path.join(ML_STATE_DIR, f"ml_log_{fname}.json")
            df[NUM_COLS].to_json(ml_log_path)

        processed.add(fname)
        save_state()
        move_to_archive(fp)

if __name__ == "__main__":
    main()
