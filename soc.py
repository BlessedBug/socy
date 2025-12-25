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

RF_CONFIDENCE_THRESHOLD = 85.0
CPU_ABUSE = 90.0
MEM_ABUSE_MB = 4096

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

if os.path.exists(PROCESSED_DB):
    processed = set(json.load(open(PROCESSED_DB)))
else:
    processed = set()

NUM_COLS = ["cpu_pct", "mem_mb", "child_count", "remote_port", "sent_mb", "recv_mb"]
TEXT_COLS = ["proc_name", "path", "source", "event_type", "username", "remote_ip", "device"]


def save_state():
    json.dump(list(processed), open(PROCESSED_DB, "w"))


def is_file_stable(path, wait_seconds=2):
    """
    Prevents processing partially written / uploading files
    by ensuring size does not change within check window.
    """
    try:
        size1 = os.path.getsize(path)
        time.sleep(wait_seconds)
        size2 = os.path.getsize(path)
        return size1 == size2
    except:
        return False


def list_pending_files():
    files = []
    for f in os.listdir(WATCH_DIR):
        if not f.endswith(".csv"):
            continue

        full = os.path.join(WATCH_DIR, f)

        # avoid reprocessing if something failed mid-run
        if f in processed:
            continue

        if not is_file_stable(full):
            continue

        files.append(full)

    return files


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
        try:
            r["mem_mb"] = float(p[6].replace("MB", ""))
        except:
            r["mem_mb"] = 0.0

        try:
            r["cpu_pct"] = float(p[7].replace("%", ""))
        except:
            r["cpu_pct"] = 0.0

        r["path"] = p[9]
        r["event_type"] = p[10]

    elif r["source"] == "network":
        r["proc_name"] = p[4]
        r["remote_ip"] = p[11]

        try:
            r["sent_mb"] = float(p[9].replace("Sent:", "").replace("MB", ""))
        except:
            r["sent_mb"] = 0.0

        try:
            r["recv_mb"] = float(p[10].replace("Recv:", "").replace("MB", ""))
        except:
            r["recv_mb"] = 0.0

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


def move_to_archive(src_path):
    base = os.path.basename(src_path)
    dst = os.path.join(PROCESSED_ARCHIVE, base)

    try:
        shutil.move(src_path, dst)
    except Exception:
        # fallback to remove if move fails
        try:
            os.remove(src_path)
        except:
            pass


def main():
    try:
        rf = joblib.load(SUPERVISED_MODEL)
        iso = joblib.load(UNSUPERVISED_MODEL)
    except Exception as e:
        print(f"[FATAL] Failed to load ML models: {e}")
        return

    files = list_pending_files()

    if not files:
        return

    for fp in files:
        fname = os.path.basename(fp)

        try:
            df = load_csv(fp)
        except Exception as e:
            print(f"[ERROR] Failed reading {fname}: {e}")
            move_to_archive(fp)
            continue

        if df.empty:
            processed.add(fname)
            save_state()
            move_to_archive(fp)
            continue

        for c in NUM_COLS:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)

        try:
            rf_preds = rf.predict(df)
            rf_probs = rf.predict_proba(df)
            iso_preds = iso.predict(df)
        except Exception as e:
            print(f"[ERROR] Model inference failed on {fname}: {e}")
            move_to_archive(fp)
            continue

        for i, row in df.iterrows():
            triggers = []

            if row["source"] == "usb":
                triggers.append("USB insertion")

            if row["cpu_pct"] >= CPU_ABUSE or row["mem_mb"] >= MEM_ABUSE_MB:
                triggers.append("Resource abuse")

            # supervised anomaly only if confidence > 85%
            try:
                conf = max(rf_probs[i]) * 100
                if rf_preds[i] == 1 and conf > RF_CONFIDENCE_THRESHOLD:
                    triggers.append(f"RandomForest confidence {round(conf,2)}%")
            except:
                pass

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
                "source_file": fname,
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

            try:
                send_email(payload)
            except Exception as e:
                print(f"[WARN] Email delivery failed: {e}")

        processed.add(fname)
        save_state()
        move_to_archive(fp)


if __name__ == "__main__":
    main()
