"""
Scheduled scans with optional email alerts.
Configure SMTP via environment variables (see .env.example).
"""

import json
import os
import smtplib
import uuid
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from scanner_lib import SimpleNetworkScanner
from cve_lookup import lookup_cves_for_scan

SCHEDULES_FILE = Path(__file__).parent / "schedules.json"
_scheduler: BackgroundScheduler | None = None
_scanner = SimpleNetworkScanner()


def _load_schedules() -> list:
    if not SCHEDULES_FILE.exists():
        return []
    try:
        return json.loads(SCHEDULES_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


def _save_schedules(schedules: list):
    SCHEDULES_FILE.write_text(json.dumps(schedules, indent=2), encoding="utf-8")


def send_alert_email(subject: str, body: str, to_email=None):
    host = os.environ.get("SMTP_HOST", "")
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER", "")
    password = os.environ.get("SMTP_PASSWORD", "")
    to_addr = to_email or os.environ.get("ALERT_EMAIL_TO", "")
    from_addr = os.environ.get("ALERT_EMAIL_FROM") or user or "scanner@localhost"

    if not host or not to_addr:
        return {"ok": False, "error": "SMTP_HOST and ALERT_EMAIL_TO required"}

    msg = MIMEMultipart()
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain", "utf-8"))

    try:
        with smtplib.SMTP(host, port, timeout=30) as server:
            server.ehlo()
            if os.environ.get("SMTP_TLS", "true").lower() != "false":
                server.starttls()
            if user and password:
                server.login(user, password)
            server.sendmail(from_addr, [to_addr], msg.as_string())
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _run_scheduled_scan(job_id: str):
    schedules = _load_schedules()
    job = next((s for s in schedules if s.get("id") == job_id), None)
    if not job or not job.get("enabled", True):
        return

    target = job["target"]
    scan_type = job.get("scan_type", "quick")
    include_cve = job.get("include_cve", False)
    use_nmap = job.get("use_nmap", False)

    lines = [f"Scheduled scan — {target}", f"Time: {datetime.now().isoformat()}", ""]

    try:
        if use_nmap:
            from nmap_scanner import nmap_port_scan, is_nmap_available

            if not is_nmap_available():
                port_data = {"error": "Nmap not available"}
            else:
                port_data = nmap_port_scan(target, scan_type)
        else:
            port_data = _scanner.port_scan(target, scan_type)

        if port_data.get("error"):
            lines.append(f"Error: {port_data['error']}")
        else:
            open_ports = port_data.get("tcp") or {}
            lines.append(f"Open ports: {len(open_ports)}")
            for port, info in sorted(open_ports.items(), key=lambda x: int(x[0])):
                lines.append(
                    f"  - {port}/{info.get('name')}: {info.get('product')} {info.get('version')}"
                )

            if include_cve and open_ports:
                cve_data = lookup_cves_for_scan(port_data, max_per_service=3)
                for svc in cve_data.get("services", []):
                    lookup = svc.get("cve_lookup", {})
                    cves = lookup.get("cves", [])
                    if cves:
                        lines.append(f"\nCVEs for {svc['product']} {svc['version']} (port {svc['port']}):")
                        for c in cves[:3]:
                            lines.append(f"  - {c['id']} [{c.get('severity')}] score={c.get('score')}")

        body = "\n".join(lines)
        job["last_run"] = datetime.now().isoformat()
        job["last_status"] = "error" if port_data.get("error") else "ok"
        for i, s in enumerate(schedules):
            if s.get("id") == job_id:
                schedules[i] = job
                break
        _save_schedules(schedules)

        email_to = job.get("email") or os.environ.get("ALERT_EMAIL_TO")
        if email_to and os.environ.get("SMTP_HOST"):
            send_alert_email(
                f"[Scanner] {target} — {job['last_status']}",
                body,
                email_to,
            )
    except Exception as e:
        job["last_run"] = datetime.now().isoformat()
        job["last_status"] = "failed"
        job["last_error"] = str(e)
        _save_schedules(schedules)
        if job.get("email") or os.environ.get("ALERT_EMAIL_TO"):
            send_alert_email(f"[Scanner] {target} — failed", str(e), job.get("email"))


def get_scheduler() -> BackgroundScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = BackgroundScheduler()
        _scheduler.start()
        for job in _load_schedules():
            if job.get("enabled", True):
                _register_job(job)
    return _scheduler


def _register_job(job: dict):
    sched = get_scheduler()
    hours = max(1, int(job.get("interval_hours", 24)))
    job_id = job["id"]
    sched.add_job(
        _run_scheduled_scan,
        trigger=IntervalTrigger(hours=hours),
        id=job_id,
        args=[job_id],
        replace_existing=True,
    )


def list_schedules():
    return _load_schedules()


def add_schedule(
    target: str,
    interval_hours: int = 24,
    scan_type: str = "quick",
    email: str | None = None,
    include_cve: bool = False,
    use_nmap: bool = False,
):
    target = (target or "").strip()
    if not target:
        return {"error": "Target is required"}

    job = {
        "id": str(uuid.uuid4())[:8],
        "target": target,
        "interval_hours": max(1, int(interval_hours)),
        "scan_type": scan_type,
        "email": email,
        "include_cve": include_cve,
        "use_nmap": use_nmap,
        "enabled": True,
        "created_at": datetime.now().isoformat(),
    }
    schedules = _load_schedules()
    schedules.append(job)
    _save_schedules(schedules)
    _register_job(job)
    return job


def remove_schedule(job_id: str):
    schedules = _load_schedules()
    new_list = [s for s in schedules if s.get("id") != job_id]
    if len(new_list) == len(schedules):
        return {"error": "Schedule not found"}
    _save_schedules(new_list)
    try:
        get_scheduler().remove_job(job_id)
    except Exception:
        pass
    return {"ok": True, "id": job_id}


def email_status():
    host = bool(os.environ.get("SMTP_HOST"))
    to = bool(os.environ.get("ALERT_EMAIL_TO"))
    return {
        "smtp_configured": host,
        "default_recipient": os.environ.get("ALERT_EMAIL_TO"),
        "ready": host and to,
    }
