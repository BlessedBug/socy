import os
import json
import time
import smtplib
import joblib
import pandas as pd
from datetime import datetime, timedelta
from google import genai
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

WATCH_DIR = r"/home/ubuntu/files"
PAYLOAD_OUT_DIR = r"/home/ubuntu/payloads"
LOOKBACK_MINUTES = 5
RF_CONFIDENCE_THRESHOLD = 85.0

SUPERVISED_MODEL = r"/home/ubuntu/socy/supervised_model.pkl"
UNSUPERVISED_MODEL = r"/home/ubuntu/socy/unsupervised_model.pkl"

GOOGLE_API_KEY = ""

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SENDER_EMAIL = "roberthazel99@gmail.com"
SENDER_PASSWORD = ""
ADMIN_EMAIL = "shehriyaraslam2.0@gmail.com"

NUM_COLS = ["cpu_pct", "mem_mb", "child_count", "remote_port", "sent_mb", "recv_mb", "mod_count"]
TEXT_COLS = ["cmdline", "path", "proc_name", "source", "event_type", "username", "remote_ip"]

client = genai.Client(api_key=GOOGLE_API_KEY)

processed_files = set()

def parse_filename_time(fname):
    try:
        ts = fname.rsplit("_", 2)[-2] + "_" + fname.rsplit("_", 1)[-1].replace(".csv", "")
        return datetime.strptime(ts, "%Y-%m-%d_%H-%M-%S")
    except:
        return None

def recent_files():
    now = datetime.now()
    start = now - timedelta(minutes=LOOKBACK_MINUTES)
    files = []
    for f in os.listdir(WATCH_DIR):
        if not f.endswith(".csv"):
            continue
        ts = parse_filename_time(f)
        if ts and start <= ts <= now:
            files.append(os.path.join(WATCH_DIR, f))
    return files

def parse_raw_log_line(line):
    parts = line.strip().split(',')
    row = {c: 0.0 for c in NUM_COLS}
    row.update({c: "" for c in TEXT_COLS})
    if len(parts) < 4:
        return row
    row["username"] = parts[2]
    row["source"] = parts[3]
    try:
        if row["source"] == "network":
            row["proc_name"] = parts[4]
            row["remote_port"] = parts[8].split(":")[-1]
            row["sent_mb"] = parts[9].replace("Sent:", "").replace("MB", "")
            row["recv_mb"] = parts[10].replace("Recv:", "").replace("MB", "")
            row["remote_ip"] = parts[11]
        elif row["source"] == "Process":
            row["proc_name"] = parts[4]
            row["mem_mb"] = parts[6].replace(" MB", "")
            row["cpu_pct"] = parts[7].replace("%", "")
            row["child_count"] = parts[8]
            row["path"] = parts[9]
            row["event_type"] = parts[10]
    except:
        pass
    return row

def load_logs(fp):
    rows = []
    with open(fp) as f:
        for line in f:
            r = parse_raw_log_line(line)
            r["original_log"] = line.strip()
            rows.append(r)
    return pd.DataFrame(rows)

def clean(df):
    for c in NUM_COLS:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)
    for c in TEXT_COLS:
        df[c] = df[c].fillna("")
    df["combined_text"] = df[TEXT_COLS].agg(" ".join, axis=1)
    return df

def ai_verdict(row):
    prompt = f"""
You are a senior Tier-3 SOC analyst.

LOG ENTRY:
{row}

Analyze process behavior, CPU, memory, ports, traffic, LOLBins abuse, persistence, lateral movement.
Ignore normal OS tasks, system services, updates, browsers, and security software.

OUTPUT STRICTLY:
VERDICT: THREAT or VERDICT: FALSE POSITIVE
REASON:
RESPONSE_ACTIONS:
"""
    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=[prompt]
        )
        return response.candidates[0].output_text.strip()
    except:
        return ""

def send_email(payload):
    subject = f"SECURITY ALERT [{payload['escalation']}] {payload['threat_count']} Threats Detected"
    body = f"""
Username: {payload['username']}
Source File: {payload['source_file']}
Threat Count: {payload['threat_count']}
Escalation: {payload['escalation']}

DETAILS:
"""
    for d in payload["details"]:
        body += f"\nProcess: {d.get('process')}\nRemote IP: {d.get('remote_ip')}\nAnalysis:\n{d.get('analysis')}\n"

    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = ADMIN_EMAIL
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)

def main():
    os.makedirs(PAYLOAD_OUT_DIR, exist_ok=True)
    files = recent_files()

    rf = joblib.load(SUPERVISED_MODEL)
    iso = joblib.load(UNSUPERVISED_MODEL)

    for fp in files:
        if fp in processed_files:
            continue

        df = load_logs(fp)
        if df.empty:
            continue

        X = clean(df.copy())
        probs = rf.predict_proba(X)
        df["RF_CONFIDENCE"] = [max(p) * 100 for p in probs]
        df["RF_PRED"] = rf.predict(X)
        df["ISO_PRED"] = iso.predict(X)

        suspicious = df[
            ((df["RF_PRED"] == 1) & (df["RF_CONFIDENCE"] >= RF_CONFIDENCE_THRESHOLD)) |
            (df["ISO_PRED"] == -1)
        ]

        confirmed = []
        for _, r in suspicious.iterrows():
            verdict = ai_verdict(r.to_dict())
            if "VERDICT: THREAT" in verdict.upper():
                confirmed.append((r, verdict))
            time.sleep(1)

        if confirmed:
            username = confirmed[0][0].get("username", "unknown")
            payload = {
                "username": username,
                "source_file": os.path.basename(fp),
                "threat_count": len(confirmed),
                "escalation": "CRITICAL" if len(confirmed) > 1 else "HIGH",
                "generated_at": datetime.now().isoformat(),
                "actions": ["lock_workstation", "disable_network", "kill_process_tree"] if len(confirmed) > 1 else ["kill_process", "block_remote_ip"],
                "details": []
            }

            for r, res in confirmed:
                payload["details"].append({
                    "process": r.get("proc_name"),
                    "remote_ip": r.get("remote_ip"),
                    "analysis": res
                })

            out = os.path.join(PAYLOAD_OUT_DIR, f"response_payload_{os.path.basename(fp)}.json")
            with open(out, "w") as f:
                json.dump(payload, f, indent=2)

            send_email(payload)

        processed_files.add(fp)

if __name__ == "__main__":
    main()

