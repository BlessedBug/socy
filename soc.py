import os
import json
import time
import smtplib
import joblib
import pandas as pd
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from google import genai

WATCH_DIR = "/home/ubuntu/files"
STATE_DIR = "/home/ubuntu/state"
PAYLOAD_DIR = "/home/ubuntu/payloads"
PROCESSED_DB = f"{STATE_DIR}/processed.json"

FORWARD_LOOK_HOURS = 5
WINDOW_MINUTES = 5

RF_CONFIDENCE_THRESHOLD = 85.0
CPU_ABUSE = 90.0
MEM_ABUSE_MB = 4096

SUPERVISED_MODEL = "/home/ubuntu/socy/supervised_model.pkl"
UNSUPERVISED_MODEL = "/home/ubuntu/socy/unsupervised_model.pkl"

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_EMAIL = os.environ.get("SMTP_EMAIL")
SMTP_PASS = os.environ.get("SMTP_PASSWORD")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL")

GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY")
client = genai.Client(api_key=GOOGLE_API_KEY)

os.makedirs(STATE_DIR, exist_ok=True)
os.makedirs(PAYLOAD_DIR, exist_ok=True)

if os.path.exists(PROCESSED_DB):
    processed = set(json.load(open(PROCESSED_DB)))
else:
    processed = set()

NUM_COLS = ["cpu_pct", "mem_mb", "child_count", "remote_port", "sent_mb", "recv_mb"]
TEXT_COLS = ["proc_name", "path", "source", "event_type", "username", "remote_ip", "device"]

def save_state():
    json.dump(list(processed), open(PROCESSED_DB, "w"))

def parse_filename_time(name):
    try:
        ts = name.rsplit("_", 2)[-2] + "_" + name.rsplit("_", 1)[-1].replace(".csv", "")
        return datetime.strptime(ts, "%Y-%m-%d_%H-%M-%S")
    except:
        return None

def select_files():
    now = datetime.now()
    target = now + timedelta(hours=FORWARD_LOOK_HOURS)
    start = target - timedelta(minutes=WINDOW_MINUTES / 2)
    end = target + timedelta(minutes=WINDOW_MINUTES / 2)
    out = []
    for f in os.listdir(WATCH_DIR):
        if not f.endswith(".csv"):
            continue
        if f in processed:
            continue
        ts = parse_filename_time(f)
        if ts and start <= ts <= end:
            out.append(os.path.join(WATCH_DIR, f))
    return out

def parse_line(line):
    p = line.strip().split(",")
    r = {c: 0.0 for c in NUM_COLS}
    r.update({c: "" for c in TEXT_COLS})
    if len(p) < 4:
        return r
    r["username"] = p[2]
    r["source"] = p[3].lower()
    if r["source"] == "usb":
        r["device"] = p[4]
        r["event_type"] = "USB_INSERT"
    elif r["source"] == "process":
        r["proc_name"] = p[4]
        r["mem_mb"] = float(p[6].replace("MB", ""))
        r["cpu_pct"] = float(p[7].replace("%", ""))
        r["path"] = p[9]
        r["event_type"] = p[10]
    elif r["source"] == "network":
        r["proc_name"] = p[4]
        r["remote_ip"] = p[11]
        r["sent_mb"] = float(p[9].replace("Sent:", "").replace("MB", ""))
        r["recv_mb"] = float(p[10].replace("Recv:", "").replace("MB", ""))
    return r

def load_csv(fp):
    rows = []
    for l in open(fp, errors="ignore"):
        r = parse_line(l)
        r["raw"] = l.strip()
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
        r = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=[prompt]
        )
        return r.candidates[0].output_text.strip()
    except:
        return ""

def send_email(payload):
    msg = MIMEMultipart()
    msg["From"] = SMTP_EMAIL
    msg["To"] = ADMIN_EMAIL
    msg["Subject"] = f"SOC ALERT [{payload['severity']}] {payload['threat_type']}"
    msg.attach(MIMEText(json.dumps(payload, indent=2), "plain"))
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as s:
        s.login(SMTP_EMAIL, SMTP_PASS)
        s.send_message(msg)

def main():
    rf = joblib.load(SUPERVISED_MODEL)
    iso = joblib.load(UNSUPERVISED_MODEL)

    for fp in select_files():
        df = load_csv(fp)
        if df.empty:
            processed.add(os.path.basename(fp))
            save_state()
            continue

        for c in NUM_COLS:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)

        rf_preds = rf.predict(df)
        rf_probs = rf.predict_proba(df)
        iso_preds = iso.predict(df)

        for i, row in df.iterrows():
            triggers = []

            if row["source"] == "usb":
                triggers.append("USB insertion")

            if row["cpu_pct"] >= CPU_ABUSE or row["mem_mb"] >= MEM_ABUSE_MB:
                triggers.append("Resource abuse")

            if rf_preds[i] == 1 and max(rf_probs[i]) * 100 >= RF_CONFIDENCE_THRESHOLD:
                triggers.append("RandomForest high confidence")

            if iso_preds[i] == -1:
                triggers.append("IsolationForest anomaly")

            if not triggers:
                continue

            verdict = ai_confirm(row.to_dict())
            if "FALSE_POSITIVE" in verdict.upper():
                continue

            payload = {
                "platform": "windows",
                "generated_at": datetime.utcnow().isoformat(),
                "source_file": os.path.basename(fp),
                "severity": "CRITICAL",
                "threat_type": row["source"],
                "user": row["username"],
                "process": row["proc_name"],
                "device": row["device"],
                "cpu_pct": row["cpu_pct"],
                "mem_mb": row["mem_mb"],
                "remote_ip": row["remote_ip"],
                "confidence_sources": triggers,
                "analysis": verdict,
                "response_plan": {
                    "kill_process": row["proc_name"],
                    "disable_usb": True if row["source"] == "usb" else False,
                    "block_network": True
                }
            }

            out = f"{PAYLOAD_DIR}/payload_{int(time.time())}.json"
            json.dump(payload, open(out, "w"), indent=2)
            send_email(payload)

        processed.add(os.path.basename(fp))
        save_state()

if __name__ == "__main__":
    main()
