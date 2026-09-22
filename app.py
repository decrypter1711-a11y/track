"""
Employee Tracker  -  sugar.relax
================================
A hardened Flask + MongoDB application for employee attendance, daily
work-updates, live activity / idle tracking and an admin console with
IP-blocking, scanner detection and per-user update exports.

Security notes (read the README for the full, honest picture):
  * Passwords are hashed with Werkzeug (PBKDF2).
  * CSRF tokens protect every POST (forms + AJAX).
  * Secret key + admin credentials come from environment variables.
  * Security headers (CSP, X-Frame-Options, nosniff, etc.) on every response.
  * A request firewall blocks known scanner user-agents, probe paths and
    request floods, recording the offending IP + reason in MongoDB so an
    admin can review and unblock from the panel.
"""

from datetime import datetime, timezone, timedelta
from functools import wraps
import csv
import io
import os
import re
import secrets
import threading
import time
import zipfile

from flask import (
    Flask, render_template, request, redirect, session, flash,
    abort, jsonify, Response, url_for
)

from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
SESSION_LIMIT = 12 * 60 * 60  # 12 hours

def session_not_expired():
    login_time = session.get("login_time")

    if not login_time:
        session["login_time"] = datetime.now(timezone.utc).timestamp()
        return True

    now = datetime.now(timezone.utc).timestamp()

    return (now - float(login_time)) < SESSION_LIMIT

# IST = UTC+5:30  (India Standard Time)
IST = timezone(timedelta(hours=5, minutes=30))

def to_ist(dt):
    """Convert a UTC datetime (naive or aware) to IST for display."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(IST)

def fmt_ist(dt, fmt="%Y-%m-%d %I:%M %p"):
    """Format a UTC datetime as IST string. Returns '' if None."""
    if dt is None:
        return ""
    return to_ist(dt).strftime(fmt)

# =========================================================================
# CONFIG
# =========================================================================

app = Flask(__name__)

# ---- File upload settings ------------------------------------------------
# Files uploaded with daily work updates are stored inside static/uploads
# and only their relative paths are saved in MongoDB.
#
# NOTE ON SERVERLESS HOSTS (Vercel, AWS Lambda, etc.): the deployed code
# lives on a read-only filesystem there — only /tmp is writable, and /tmp
# is wiped between invocations/cold starts, so uploaded files will NOT
# persist. On Vercel (VERCEL=1 is set automatically) we fall back to /tmp
# so the app doesn't crash; treat file uploads as "best effort / temporary"
# on this host. For durable uploads on a serverless host, store the file
# in a real object store (e.g. S3/Cloudinary) instead of local disk.
if os.environ.get("VERCEL"):
    UPLOAD_FOLDER = "/tmp/uploads"
else:
    UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
ALLOWED_EXTENSIONS = {
    "png", "jpg", "jpeg", "gif",
    "pdf", "doc", "docx", "xls", "xlsx", "txt"
}
try:
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
except OSError:
    UPLOAD_FOLDER = "/tmp/uploads"
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB upload limit


# ---- Persistent SECRET_KEY -----------------------------------------------
# On first run, a key is generated and written to .secret_key (next to
# app.py). Subsequent restarts reuse the same key so sessions survive.
# Override entirely by setting the SECRET_KEY environment variable.
_SECRET_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".secret_key")

def _load_or_create_secret_key():
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    if os.path.exists(_SECRET_KEY_FILE):
        with open(_SECRET_KEY_FILE, "r") as f:
            key = f.read().strip()
            if key:
                return key
    key = secrets.token_hex(64)
    try:
        with open(_SECRET_KEY_FILE, "w") as f:
            f.write(key)
    except OSError:
        pass  # read-only filesystem: fall back to in-memory (still stable this run)
    return key

app.secret_key = _load_or_create_secret_key()

# ---- Admin credentials ---------------------------------------------------
# Username is plain text (it's a login name, not a secret).
# Password is stored as a Werkzeug PBKDF2 hash at startup so it is never
# compared in plain text at runtime. Override via environment variables.
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "rootxsplit")
_raw_admin_password = os.environ.get("ADMIN_PASSWORD", "rootx1740")
ADMIN_PASSWORD_HASH = generate_password_hash(_raw_admin_password)
del _raw_admin_password  # remove plain text from memory immediately

# Activity / progress tuning (seconds)
# ONLINE_WINDOW: an employee is considered Online only while their
# last_active timestamp is within this window.  The browser sends a
# heartbeat every 30 s, so 75 s gives two missed beats before we flip
# to Offline — fast enough to catch a closed laptop/tab without false
# positives from a slow connection or a brief browser throttle.
ONLINE_WINDOW = 75            # seconds (was 300 — trimmed so closed systems go Offline quickly)
IDLE_THRESHOLD = 60           # client-side: no input for this long => idle
PROGRESS_INTERVAL = 2 * 60 * 60   # employee must post an update every 2h

# Request-firewall tuning
RATE_LIMIT_WINDOW = 10        # seconds
RATE_LIMIT_MAX = 60           # max requests per IP per window before block

# Harden session cookies
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Set SESSION_COOKIE_SECURE=1 in env when serving over HTTPS
    SESSION_COOKIE_SECURE=bool(int(os.environ.get("COOKIE_SECURE", "0"))),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)

# =========================================================================
# DATABASE
# =========================================================================

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
client = MongoClient(MONGO_URI)
db = client["employee_tracker"]

employees_col = db["employees"]
updates_col = db["daily_updates"]
attendance_col = db["attendance"]
activity_col = db["activity"]
blocked_col = db["blocked_ips"]
login_events_col = db["login_events"]   # audit log of employee logins/logouts

# username (login name) and email are both unique. display_name is NOT.
employees_col.create_index("username", unique=True)
employees_col.create_index("email", unique=True)
blocked_col.create_index("ip", unique=True)
activity_col.create_index([("employee_id", 1), ("date", 1)], unique=True)
# Attendance is queried by (employee_id, date) on every check-in/out.
attendance_col.create_index([("employee_id", 1), ("date", 1)])

# Warn loudly if the default admin password is still in use.
import sys as _sys
if not os.environ.get("ADMIN_PASSWORD"):
    print(
        "\n⚠️  WARNING: ADMIN_PASSWORD env var is not set. "
        "The default admin password is in use — change it before deploying.\n",
        file=_sys.stderr,
    )

# =========================================================================
# BACKGROUND SWEEPER — mark stale employees Offline
# =========================================================================
# The browser sends a heartbeat every 30 s.  If we haven't heard from an
# employee for longer than ONLINE_WINDOW, we flip is_online=False in the
# database so the admin Live Monitor and Employee list show Offline
# immediately — even when the user closed their laptop or lost power.
# This runs in a daemon thread so it stops automatically when Flask exits.

def _offline_sweeper():
    """Background thread: flip is_online=False for silent employees."""
    while True:
        time.sleep(60)   # check every 60 s
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(seconds=ONLINE_WINDOW)
            # Match employees who are flagged online but whose last_active
            # has gone past the cutoff (or is missing).
            employees_col.update_many(
                {
                    "is_online": True,
                    "$or": [
                        {"last_active": {"$lt": cutoff}},
                        {"last_active": None},
                    ],
                },
                {"$set": {"is_online": False}},
            )
        except Exception:
            pass   # don't crash the sweeper on transient DB errors


_sweeper = threading.Thread(target=_offline_sweeper, daemon=True, name="offline-sweeper")
_sweeper.start()



# Known offensive-tool signatures in the User-Agent string.
SCANNER_UA = re.compile(
    r"(sqlmap|nikto|nmap|masscan|nuclei|acunetix|dirbuster|gobuster|"
    r"wpscan|nessus|openvas|zgrab|fimap|whatweb|arachni|metasploit|"
    r"hydra|w3af|skipfish|joomscan|httrack|libwww|x_burp)",
    re.IGNORECASE,
)

# Paths that legitimate users of THIS app never request - probing them
# is a strong signal of an automated scan.
PROBE_PATHS = (
    "/.env", "/.git", "/.aws", "/.ssh", "/wp-login.php", "/wp-admin",
    "/phpmyadmin", "/phpMyAdmin", "/admin.php", "/xmlrpc.php", "/shell",
    "/config.php", "/.htaccess", "/vendor/", "/server-status",
    "/.vscode", "/actuator", "/cgi-bin/", "/etc/passwd", "/owa/",
    "/solr/", "/console", "/struts", "/jenkins",
)

# In-memory rate-limit table: ip -> list[timestamps]. Resets on restart.
_rate_table = {}
# Small cache of currently-blocked IPs so we don't hit Mongo every request.
_blocked_cache = set()

# Trusted proxy IPs: set TRUSTED_PROXIES env var as comma-separated list.
# Only read X-Forwarded-For when the direct connection comes from a trusted proxy.
# Example: TRUSTED_PROXIES=10.0.0.1,10.0.0.2
_TRUSTED_PROXIES = {
    ip.strip()
    for ip in os.environ.get("TRUSTED_PROXIES", "").split(",")
    if ip.strip()
}


def _refresh_blocked_cache():
    global _blocked_cache
    _blocked_cache = {d["ip"] for d in blocked_col.find({}, {"ip": 1})}


_refresh_blocked_cache()


def client_ip():
    """Best-effort real client IP.
    X-Forwarded-For is only trusted when the direct TCP connection comes from
    a known proxy (set TRUSTED_PROXIES env var).  Without that guard any client
    can spoof the header to bypass rate-limiting and IP blocking.
    """
    remote = request.remote_addr or "unknown"
    if _TRUSTED_PROXIES and remote in _TRUSTED_PROXIES:
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return remote


def block_ip(ip, reason):
    """Persist a block + update the cache. Idempotent."""
    if ip in ("127.0.0.1", "localhost"):
        # Never auto-block the local host (would lock out a local admin).
        return
    blocked_col.update_one(
        {"ip": ip},
        {"$setOnInsert": {
            "ip": ip,
            "reason": reason,
            "user_agent": request.headers.get("User-Agent", "")[:300],
            "path": request.path[:200],
            "blocked_at": datetime.now(timezone.utc),
        }},
        upsert=True,
    )
    _blocked_cache.add(ip)


def _rate_limited(ip):
    now = time.time()
    bucket = [t for t in _rate_table.get(ip, []) if now - t < RATE_LIMIT_WINDOW]
    bucket.append(now)
    _rate_table[ip] = bucket

    # Periodically evict stale entries so _rate_table doesn't grow unbounded
    # under heavy scanner traffic.  Evict every ~500 calls (cheap modulo check).
    if len(_rate_table) > 500 and int(now) % 10 == 0:
        cutoff = now - RATE_LIMIT_WINDOW
        stale = [k for k, v in _rate_table.items() if not v or v[-1] < cutoff]
        for k in stale:
            del _rate_table[k]

    return len(bucket) > RATE_LIMIT_MAX


@app.before_request
def firewall():
    ip = client_ip()

    # 1. Already blocked?  ->  hard stop.
    if ip in _blocked_cache:
        abort(403)

    ua = request.headers.get("User-Agent", "")
    path = request.path

    # 2. Offensive-tool user agent.
    if SCANNER_UA.search(ua):
        block_ip(ip, f"Scanner user-agent detected: {ua[:120]}")
        abort(403)

    # 3. Missing User-Agent on a non-static request is highly abnormal
    #    for a browser and typical of scripted scanners.
    if not ua and not path.startswith("/static"):
        block_ip(ip, "Missing User-Agent header (scripted client)")
        abort(403)

    # 4. Probing for paths this app does not have.
    low = path.lower()
    if any(low.startswith(p.lower()) or p.lower() in low for p in PROBE_PATHS):
        block_ip(ip, f"Probed non-existent sensitive path: {path[:120]}")
        abort(403)

    # 5. Request flood.
    if _rate_limited(ip):
        block_ip(ip, "Request flood / rate limit exceeded")
        abort(403)


@app.after_request
def security_headers(resp):
    """Defence-in-depth response headers."""
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    # CSP - allow the CDNs the templates use (fonts, icons, chart.js).
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com "
        "https://cdn.jsdelivr.net; "
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'"
    )
    return resp


# =========================================================================
# CSRF  (manual, no extra dependency)
# =========================================================================

def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(32)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def seed_csrf():
    """Seed CSRF token into every session on first request so admin login
    works even on a brand-new session (token exists before template renders)."""
    csrf_token()  # no-op if already set


@app.context_processor
def inject_activity_config():
    """Expose activity-tracking config to every employee page automatically."""
    if "employee_id" in session:
        since = seconds_since_last_update(session["employee_id"])
        secs_left = None if since is None else max(0, PROGRESS_INTERVAL - since)
        return {
            "config_logged_in": True,
            "idle_threshold": IDLE_THRESHOLD,
            "seconds_left": secs_left,
        }
    return {"config_logged_in": False, "idle_threshold": IDLE_THRESHOLD,
            "seconds_left": None}


@app.before_request
def csrf_protect():
    if request.method == "POST":
        # /offline and /logout-beacon are called by navigator.sendBeacon which
        # cannot set custom headers — they are protected by the session cookie instead.
        if request.path in ("/offline", "/logout-beacon"):
            return
        sent = request.form.get("_csrf") or request.headers.get("X-CSRFToken")
        if not sent or sent != session.get("_csrf"):
            abort(400, description="CSRF validation failed")


# =========================================================================
# AUTH DECORATORS
# =========================================================================

def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):

        if "employee_id" not in session:
            return redirect("/")

        if not session_not_expired():
            session.clear()
            flash("Your session expired after 12 hours. Please login again.")
            return redirect("/")

        return f(*a, **kw)

    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if "admin" not in session:
            return redirect("/admin")
        return f(*a, **kw)
    return wrapper


# =========================================================================
# HELPERS
# =========================================================================

def get_today_str():
    # Use IST date so check-in date matches the employee's local calendar,
    # not the UTC date (which can be a day behind after midnight IST).
    return datetime.now(IST).strftime("%Y-%m-%d")


def format_time(dt):
    if dt is None:
        return "--:-- --"
    return fmt_ist(dt, "%I:%M %p")


def calc_hours(check_in, check_out):
    if check_in is None or check_out is None:
        return "0h 00m"
    # Normalise to UTC-aware so mixed naive/aware datetimes don't crash
    if check_in.tzinfo is None:
        check_in = check_in.replace(tzinfo=timezone.utc)
    if check_out.tzinfo is None:
        check_out = check_out.replace(tzinfo=timezone.utc)
    diff = check_out - check_in
    total_minutes = int(diff.total_seconds() // 60)
    if total_minutes < 0:
        return "0h 00m"
    h, m = divmod(total_minutes, 60)
    return f"{h}h {m:02d}m"


def fmt_duration(seconds):
    seconds = int(seconds or 0)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m:02d}m"
    if m:
        return f"{m}m {s:02d}s"
    return f"{s}s"


def current_employee():
    from bson import ObjectId
    try:
        return employees_col.find_one({"_id": ObjectId(session["employee_id"])})
    except Exception:
        return None


def seconds_since_last_update(employee_id):
    last = updates_col.find_one(
        {"employee_id": employee_id}, sort=[("date", -1)]
    )
    if not last:
        return None  # never updated
    delta = datetime.now(timezone.utc) - last["date"].replace(tzinfo=timezone.utc)
    return int(delta.total_seconds())


def is_online(emp):
    # Explicit logout sets is_online=False — honour it immediately
    # regardless of how recent last_active is.
    if emp.get("is_online") is False:
        return False
    la = emp.get("last_active")
    if not la:
        return False
    if la.tzinfo is None:
        la = la.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - la).total_seconds() <= ONLINE_WINDOW


# =========================================================================
# PUBLIC / EMPLOYEE AUTH
# =========================================================================

@app.route("/")
def home():
    if "employee_id" in session:
        return redirect("/dashboard")
    return render_template("login.html")


@app.route("/register")
def register():
    # Self-registration is disabled — only admins can add employees via
    # /admin/add-employee.  The route is kept so stale links get a clean 404
    # rather than a "not found" from Flask's router.
    abort(404)


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"].strip().lower()
    password = request.form["password"]
    employee = employees_col.find_one({"username": username})
    if employee and check_password_hash(employee["password"], password):
        session.clear()
        session["employee_id"] = str(employee["_id"])
        session["display_name"] = employee["display_name"]
        session["username"] = employee["username"]
        session["login_time"] = datetime.now(timezone.utc).timestamp()
        employees_col.update_one(
            {"_id": employee["_id"]},
            {"$set": {"last_active": datetime.now(timezone.utc), "is_online": True}},
        )
        login_events_col.insert_one({
            "employee_id": str(employee["_id"]),
            "username": employee["username"],
            "display_name": employee["display_name"],
            "event": "login",
            "timestamp": datetime.now(timezone.utc),
            "ip": client_ip(),
            "user_agent": request.headers.get("User-Agent", "")[:200],
        })
        return redirect("/dashboard")
    return render_template("login.html", error="Invalid username or password")


@app.route("/logout")
def logout():
    if "employee_id" in session:
        from bson import ObjectId
        login_events_col.insert_one({
            "employee_id": session["employee_id"],
            "username": session.get("username", ""),
            "display_name": session.get("display_name", ""),
            "event": "logout",
            "timestamp": datetime.now(timezone.utc),
            "ip": client_ip(),
            "user_agent": request.headers.get("User-Agent", "")[:200],
        })
        # Immediately mark employee offline so admin Live Monitor shows
        # them as Offline right away instead of waiting for the 90s window.
        try:
            employees_col.update_one(
                {"_id": ObjectId(session["employee_id"])},
                {"$set": {"last_active": None, "is_online": False}},
            )
        except Exception:
            pass
    session.clear()
    return redirect("/")


# =========================================================================
# EMPLOYEE APP
# =========================================================================

@app.route("/dashboard")
@login_required
def dashboard():
    emp = current_employee()
    if not emp:
        session.clear()
        return redirect("/")
    emp_id = session["employee_id"]

    total_updates = updates_col.count_documents({"employee_id": emp_id})
    total_attendance = attendance_col.count_documents({"employee_id": emp_id})

    today_str = get_today_str()
    today_record = attendance_col.find_one({"employee_id": emp_id, "date": today_str})

    check_in_time = check_out_time = "--:--"
    hours_worked = "0h 00m"
    today_status = "Not Checked In"
    if today_record:
        check_in_time = format_time(today_record.get("check_in"))
        check_out_time = format_time(today_record.get("check_out"))
        hours_worked = calc_hours(today_record.get("check_in"), today_record.get("check_out"))
        today_status = today_record.get("status", "Half Day")

    since = seconds_since_last_update(emp_id)
    secs_left = None if since is None else max(0, PROGRESS_INTERVAL - since)

    return render_template(
        "dashboard.html",
        name=emp["display_name"],
        username=emp["username"],
        total_updates=total_updates,
        total_attendance=total_attendance,
        check_in_time=check_in_time,
        check_out_time=check_out_time,
        hours_worked=hours_worked,
        today_status=today_status,
        progress_interval=PROGRESS_INTERVAL,
        seconds_since_update=since,
        seconds_left=secs_left,
    )


@app.route("/dashboard-stats")
@login_required
def dashboard_stats():
    """JSON endpoint for live dashboard card refresh (no full page reload)."""
    emp_id = session["employee_id"]
    today_str = get_today_str()
    today_record = attendance_col.find_one({"employee_id": emp_id, "date": today_str})

    check_in_time = check_out_time = "--:--"
    hours_worked = "0h 00m"
    today_status = "Not Checked In"
    if today_record:
        check_in_time  = format_time(today_record.get("check_in"))
        check_out_time = format_time(today_record.get("check_out"))
        hours_worked   = calc_hours(today_record.get("check_in"), today_record.get("check_out"))
        today_status   = today_record.get("status", "Half Day")

    return jsonify({
        "today_status":    today_status,
        "hours_worked":    hours_worked,
        "check_in_time":   check_in_time,
        "check_out_time":  check_out_time,
        "total_updates":   updates_col.count_documents({"employee_id": emp_id}),
        "total_attendance": attendance_col.count_documents({"employee_id": emp_id}),
    })


@app.route("/check-in", methods=["POST"])
@login_required
def check_in():
    emp_id = session["employee_id"]
    today_str = get_today_str()
    if attendance_col.find_one({"employee_id": emp_id, "date": today_str}):
        flash("You have already checked in today.")
        return redirect("/dashboard")
    attendance_col.insert_one({
        "employee_id": emp_id,
        "username": session["username"],
        "display_name": session["display_name"],
        "status": "Half Day",
        "check_in": datetime.now(timezone.utc),
        "check_out": None,
        "date": today_str,
    })
    flash("Checked in successfully!")
    return redirect("/dashboard")


@app.route("/check-out", methods=["POST"])
@login_required
def check_out():
    emp_id = session["employee_id"]
    today_str = get_today_str()
    record = attendance_col.find_one({"employee_id": emp_id, "date": today_str})
    if not record:
        flash("No check-in found for today. Please check in first.")
        return redirect("/dashboard")
    if record.get("check_out"):
        flash("You have already checked out today.")
        return redirect("/dashboard")
    attendance_col.update_one(
        {"_id": record["_id"]},
        {"$set": {"check_out": datetime.now(timezone.utc), "status": "Present"}},
    )
    flash("Checked out successfully!")
    return redirect("/dashboard")


@app.route("/attendance")
@login_required
def attendance():
    emp_id = session["employee_id"]
    cur = attendance_col.find({"employee_id": emp_id}).sort("date", -1)
    records = [{
        "date": r.get("date", ""),
        "status": r.get("status", ""),
        "check_in": format_time(r.get("check_in")),
        "check_out": format_time(r.get("check_out")),
        "hours": calc_hours(r.get("check_in"), r.get("check_out")),
    } for r in cur]
    return render_template("attendance.html", attendance=records)


def allowed_file(filename):
    """Return True only for safe upload extensions."""
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


@app.route("/add-update", methods=["GET", "POST"])
@login_required
def add_update():
    if request.method == "POST":
        text = request.form["work_update"].strip()

        attachments = []
        files = request.files.getlist("attachments")

        for file in files:
            if file and file.filename:
                if not allowed_file(file.filename):
                    flash("Invalid file type. Allowed: images, PDF, Word, Excel, TXT.")
                    return redirect("/add-update")

                original_name = secure_filename(file.filename)
                file_ext = original_name.rsplit(".", 1)[1].lower()
                unique_name = f"{session['employee_id']}_{int(time.time())}_{secrets.token_hex(4)}_{original_name}"

                save_path = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)
                file.save(save_path)

                attachments.append({
                    "filename": original_name,
                    "path": f"uploads/{unique_name}",
                    "type": file_ext,
                })

        if text:
            updates_col.insert_one({
                "employee_id": session["employee_id"],
                "username": session["username"],
                "display_name": session["display_name"],
                "work_update": text,
                "attachments": attachments,
                "date": datetime.now(timezone.utc),
            })
            flash("Update submitted successfully!")

        return redirect("/updates")

    return render_template("add_update.html")


@app.route("/updates")
@login_required
def updates():
    cur = updates_col.find({"employee_id": session["employee_id"]}).sort("date", -1)
    data = []
    for u in cur:
        d = dict(u)
        d["date_str"] = fmt_ist(u["date"]) if u.get("date") else ""
        data.append(d)
    return render_template("updates.html", updates=data)


@app.route("/heartbeat", methods=["POST"])
@login_required
def heartbeat():
    """
    Browser sends activity every 30 seconds.

    Active = mouse/keyboard activity
    Idle   = no mouse/keyboard activity
    Away   = tab hidden/minimized

    Idle and Away can increase together.
    """

    data = request.get_json(silent=True) or {}

    active = int(data.get("active", 0) or 0)
    idle = int(data.get("idle", 0) or 0)
    away = int(data.get("away", 0) or 0)

    idle_events = int(data.get("idle_events", 0) or 0)
    away_events = int(data.get("away_events", 0) or 0)

    active = max(0, min(active, 3600))
    idle = max(0, min(idle, 3600))
    away = max(0, min(away, 3600))

    idle_events = max(0, min(idle_events, 1000))
    away_events = max(0, min(away_events, 1000))

    emp_id = session["employee_id"]
    today_str = get_today_str()
    now = datetime.now(timezone.utc)

    activity_col.update_one(
        {
            "employee_id": emp_id,
            "date": today_str
        },
        {
            "$inc": {
                "active_seconds": active,
                "idle_seconds": idle,
                "away_seconds": away,
                "idle_events": idle_events,
                "away_events": away_events,
            },
            "$set": {
                "last_heartbeat": now,
                "username": session["username"],
                "display_name": session["display_name"],
            }
        },
        upsert=True,
    )

    from bson import ObjectId

    employees_col.update_one(
        {"_id": ObjectId(emp_id)},
        {
            "$set": {
                "last_active": now,
                "is_online": True
            }
        }
    )

    since = seconds_since_last_update(emp_id)

    secs_left = (
        None
        if since is None
        else max(0, PROGRESS_INTERVAL - since)
    )

    return jsonify({
        "ok": True,
        "seconds_left": secs_left
    })

@app.route("/offline", methods=["POST"])
@login_required
def mark_offline():
    """Called by navigator.sendBeacon on page/tab close.
    Immediately flips the employee to Offline in the DB so the admin
    Live Monitor updates within seconds rather than waiting for the
    ONLINE_WINDOW to expire.
    sendBeacon sends a POST with Content-Type text/plain and no body,
    so we skip CSRF validation for this one endpoint — it is guarded
    by the session cookie (login_required) instead."""
    from bson import ObjectId
    try:
        employees_col.update_one(
            {"_id": ObjectId(session["employee_id"])},
            {"$set": {"last_active": None, "is_online": False}},
        )
    except Exception:
        pass
    return "", 204


@app.route("/logout-beacon", methods=["POST"])
@login_required
def logout_beacon():
    """
    Called by navigator.sendBeacon when browser/tab is closed or refreshed.

    Important:
    Browser refresh and tab close both trigger sendBeacon.
    So we should NOT clear session here.
    Otherwise employee gets logged out on every refresh.

    This route only marks employee offline.
    Actual logout should happen only from /logout button.
    """

    from bson import ObjectId

    if "employee_id" in session:
        try:
            employees_col.update_one(
                {"_id": ObjectId(session["employee_id"])},
                {
                    "$set": {
                        "last_active": None,
                        "is_online": False
                    }
                }
            )
        except Exception:
            pass

    return "", 204


# =========================================================================
# ADMIN
# =========================================================================

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]
        if u == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, p):
            session.clear()
            session["admin"] = True
            return redirect("/admin-dashboard")
        return render_template("admin_login.html", error="Invalid Admin Login")
    return render_template("admin_login.html")


@app.route("/admin-logout")
def admin_logout():
    session.pop("admin", None)
    return redirect("/admin")


@app.route("/admin-dashboard")
@admin_required
def admin_dashboard():
    updates_list = list(updates_col.find().sort("date", -1).limit(200))
    for u in updates_list:
        u["date_str"] = fmt_ist(u["date"]) if u.get("date") else ""

    total_employees = employees_col.count_documents({})
    total_updates = updates_col.count_documents({})
    blocked_count = blocked_col.count_documents({})
    online_count = sum(1 for e in employees_col.find({}, {"last_active": 1, "is_online": 1}) if is_online(e))

    return render_template(
        "admin_dashboard.html",
        updates=updates_list,
        total_employees=total_employees,
        total_updates=total_updates,
        blocked_count=blocked_count,
        online_count=online_count,
    )



@app.route("/admin-employees")
@admin_required
def admin_employees():
    today_str = get_today_str()
    rows = []
    for e in employees_col.find().sort("display_name", 1):
        eid = str(e["_id"])
        act = activity_col.find_one({"employee_id": eid, "date": today_str}) or {}
        since = seconds_since_last_update(eid)
        # Minutes since last input event (browser heartbeat last_heartbeat
        # is updated every 30s while the tab is open).
        last_hb = act.get("last_heartbeat")
        if last_hb:
            if last_hb.tzinfo is None:
                last_hb = last_hb.replace(tzinfo=timezone.utc)
            mins_since_hb = int((datetime.now(timezone.utc) - last_hb).total_seconds() // 60)
        else:
            mins_since_hb = None
        rows.append({
            "id": eid,
            "username": e.get("username", ""),
            "display_name": e.get("display_name", ""),
            "email": e.get("email", ""),
            "online": is_online(e),
            "last_active": (fmt_ist(e["last_active"])
                            if e.get("last_active") else "Never"),
            "active_today": fmt_duration(act.get("active_seconds", 0)),
            "idle_today": fmt_duration(act.get("idle_seconds", 0)),
            "away_today": fmt_duration(act.get("away_seconds", 0)),
            "idle_events": act.get("idle_events", 0),
            "away_events": act.get("away_events", 0),
            "mins_since_input": mins_since_hb,
            "update_overdue": (since is None or since > PROGRESS_INTERVAL),
            "update_count": updates_col.count_documents({"employee_id": eid}),
        })
    return render_template("admin_employees.html", employees=rows)


@app.route("/admin/add-employee", methods=["GET", "POST"])
@admin_required
def admin_add_employee():
    if request.method == "POST":
        username = request.form["username"].strip().lower()
        display_name = request.form["display_name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        if not re.fullmatch(r"[a-z0-9_.]{3,30}", username):
            return render_template("add_employee.html",
                                   error="Username must be 3-30 chars: a-z 0-9 _ .")
        if employees_col.find_one({"username": username}):
            return render_template("add_employee.html", error="Username already taken.")
        if employees_col.find_one({"email": email}):
            return render_template("add_employee.html", error="Email already registered.")
        try:
            employees_col.insert_one({
                "username": username,
                "display_name": display_name,
                "email": email,
                "password": generate_password_hash(password),
                "created_at": datetime.now(timezone.utc),
                "last_active": None,
            })
            flash("Employee registered successfully!")
            return redirect("/admin-employees")
        except Exception:
            return render_template("add_employee.html", error="Duplicate username or email.")
    return render_template("add_employee.html")


@app.route("/admin-attendance")
@admin_required
def admin_attendance():
    search = request.args.get("search", "")
    date_filter = request.args.get("date", "")
    query = {}
    if search:
        query["display_name"] = {"$regex": re.escape(search), "$options": "i"}
    if date_filter:
        query["date"] = date_filter

    cur = attendance_col.find(query).sort("date", -1)
    records = [{
        "display_name": r.get("display_name", r.get("employee_name", "")),
        "username": r.get("username", ""),
        "date": r.get("date", ""),
        "status": r.get("status", ""),
        "check_in": format_time(r.get("check_in")),
        "check_out": format_time(r.get("check_out")),
        "hours": calc_hours(r.get("check_in"), r.get("check_out")),
    } for r in cur]

    total_records = attendance_col.count_documents({})
    present_count = attendance_col.count_documents({"status": "Present"})
    half_day_count = attendance_col.count_documents({"status": "Half Day"})
    # Pending = checked in today but not yet checked out.
    pending_checkout = attendance_col.count_documents(
        {"check_out": None, "date": get_today_str()}
    )

    return render_template(
        "admin_attendance.html",
        attendance=records, total_records=total_records,
        present_count=present_count, half_day_count=half_day_count,
        pending_checkout=pending_checkout,
    )


# ---- Blocked IP management ------------------------------------------------

@app.route("/admin-blocked")
@admin_required
def admin_blocked():
    rows = []
    for b in blocked_col.find().sort("blocked_at", -1):
        rows.append({
            "ip": b.get("ip", ""),
            "reason": b.get("reason", ""),
            "user_agent": b.get("user_agent", ""),
            "path": b.get("path", ""),
            "blocked_at": (fmt_ist(b["blocked_at"])
                           if b.get("blocked_at") else ""),
        })
    return render_template("admin_blocked.html", blocked=rows)


@app.route("/admin-unblock", methods=["POST"])
@admin_required
def admin_unblock():
    ip = request.form.get("ip", "")
    if ip:
        blocked_col.delete_one({"ip": ip})
        _blocked_cache.discard(ip)
        _rate_table.pop(ip, None)
        flash(f"Unblocked {ip}")
    return redirect("/admin-blocked")


# ---- Manage a single employee (edit updates + activity) -------------------

@app.route("/admin/manage/<employee_id>")
@admin_required
def admin_manage(employee_id):
    from bson import ObjectId
    try:
        emp = employees_col.find_one({"_id": ObjectId(employee_id)})
    except Exception:
        emp = None
    if not emp:
        flash("Employee not found.")
        return redirect("/admin-employees")

    date_str = request.args.get("date", get_today_str())
    act = activity_col.find_one({"employee_id": employee_id, "date": date_str}) or {}

    cur = updates_col.find({"employee_id": employee_id}).sort("date", -1)
    updates_list = []
    for u in cur:
        updates_list.append({
            "id": str(u["_id"]),
            "work_update": u.get("work_update", ""),
            "date_str": fmt_ist(u["date"]) if u.get("date") else "",
            "admin_added": u.get("admin_added", False),
            "edited_by_admin": u.get("edited_by_admin", False),
        })

    return render_template(
        "admin_manage.html",
        emp={
            "id": employee_id,
            "username": emp.get("username", ""),
            "display_name": emp.get("display_name", ""),
            "email": emp.get("email", ""),
            "online": is_online(emp),
        },
        date_str=date_str,
        active_minutes=round((act.get("active_seconds", 0) or 0) / 60, 1),
        idle_minutes=round((act.get("idle_seconds", 0) or 0) / 60, 1),
        idle_events=act.get("idle_events", 0),
        updates=updates_list,
    )


@app.route("/admin/manage/<employee_id>/activity", methods=["POST"])
@admin_required
def admin_edit_activity(employee_id):
    """Admin manually corrects an employee's activity for a date.
    Useful when the browser mouse/keyboard tracker missed time, or to
    reclassify idle ('inactive') time as active."""
    date_str = request.form.get("date", get_today_str())

    def to_int(name, default=0):
        try:
            return max(0, int(float(request.form.get(name, default))))
        except (TypeError, ValueError):
            return default

    active_seconds = to_int("active_minutes") * 60
    idle_seconds = to_int("idle_minutes") * 60
    idle_events = to_int("idle_events")

    activity_col.update_one(
        {"employee_id": employee_id, "date": date_str},
        {"$set": {
            "active_seconds": active_seconds,
            "idle_seconds": idle_seconds,
            "idle_events": idle_events,
            "admin_adjusted": True,
            "adjusted_at": datetime.now(timezone.utc),
            "username": session.get("username", ""),
        }},
        upsert=True,
    )
    flash(f"Activity for {date_str} updated.")
    return redirect(url_for("admin_manage", employee_id=employee_id, date=date_str))


@app.route("/admin/manage/<employee_id>/add-update", methods=["POST"])
@admin_required
def admin_add_update_for(employee_id):
    """Admin posts a work update on behalf of an employee (e.g. if they
    didn't update themselves)."""
    from bson import ObjectId
    emp = employees_col.find_one({"_id": ObjectId(employee_id)})
    if not emp:
        flash("Employee not found.")
        return redirect("/admin-employees")
    text = request.form.get("work_update", "").strip()
    if text:
        updates_col.insert_one({
            "employee_id": employee_id,
            "username": emp.get("username", ""),
            "display_name": emp.get("display_name", ""),
            "work_update": text,
            "date": datetime.now(timezone.utc),
            "admin_added": True,
        })
        flash("Update added on behalf of employee.")
    return redirect(url_for("admin_manage", employee_id=employee_id))


@app.route("/admin/edit-update/<update_id>", methods=["POST"])
@admin_required
def admin_edit_update(update_id):
    from bson import ObjectId
    text = request.form.get("work_update", "").strip()
    employee_id = request.form.get("employee_id", "")
    if text:
        updates_col.update_one(
            {"_id": ObjectId(update_id)},
            {"$set": {
                "work_update": text,
                "edited_by_admin": True,
                "edited_at": datetime.now(timezone.utc),
            }},
        )
        flash("Update edited.")
    return redirect(url_for("admin_manage", employee_id=employee_id))


@app.route("/admin/delete-update/<update_id>", methods=["POST"])
@admin_required
def admin_delete_update(update_id):
    from bson import ObjectId
    employee_id = request.form.get("employee_id", "")
    updates_col.delete_one({"_id": ObjectId(update_id)})
    flash("Update deleted.")
    return redirect(url_for("admin_manage", employee_id=employee_id))


# ---- Live monitor: who's currently logged in + activity at a glance ------

@app.route("/admin/live-monitor")
@admin_required
def admin_live_monitor():
    today_str = get_today_str()
    online_rows, idle_rows, offline_rows = [], [], []
    for e in employees_col.find().sort("display_name", 1):
        eid = str(e["_id"])
        act = activity_col.find_one({"employee_id": eid, "date": today_str}) or {}
        last_hb = act.get("last_heartbeat") or e.get("last_active")
        mins_inactive = None
        if last_hb:
            if last_hb.tzinfo is None:
                last_hb = last_hb.replace(tzinfo=timezone.utc)
            mins_inactive = int((datetime.now(timezone.utc) - last_hb).total_seconds() // 60)

        row = {
            "id": eid,
            "username": e.get("username", ""),
            "display_name": e.get("display_name", ""),
            "active_today": fmt_duration(act.get("active_seconds", 0)),
            "idle_today": fmt_duration(act.get("idle_seconds", 0)),
            "away_today": fmt_duration(act.get("away_seconds", 0)),
            "idle_events": act.get("idle_events", 0),
            "away_events": act.get("away_events", 0),
            "mins_inactive": mins_inactive,
            "last_active": (fmt_ist(e["last_active"])
                            if e.get("last_active") else "Never"),
        }
        if is_online(e):
            online_rows.append(row)
        elif mins_inactive is not None and mins_inactive < 60 * 8:
            # heartbeat seen recently-ish (within today) but not in last 60s -> idle
            idle_rows.append(row)
        else:
            offline_rows.append(row)

    return render_template(
        "admin_live_monitor.html",
        online_rows=online_rows,
        idle_rows=idle_rows,
        offline_rows=offline_rows,
    )


@app.route("/admin/login-history")
@admin_required
def admin_login_history():
    cur = login_events_col.find().sort("timestamp", -1).limit(500)
    rows = []
    for ev in cur:
        rows.append({
            "when": fmt_ist(ev["timestamp"], "%Y-%m-%d %I:%M:%S %p") if ev.get("timestamp") else "",
            "event": ev.get("event", ""),
            "display_name": ev.get("display_name", ""),
            "username": ev.get("username", ""),
            "ip": ev.get("ip", ""),
            "user_agent": (ev.get("user_agent", "") or "")[:80],
        })
    return render_template("admin_login_history.html", events=rows)


# ---- PDF export of an employee's updates ---------------------------------

def _resolve_range(args):
    """Resolve ?day=YYYY-MM-DD | ?month=YYYY-MM | ?days=N | (default last 7d)."""
    now = datetime.now(timezone.utc)
    if args.get("day"):
        try:
            d = datetime.strptime(args["day"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            return d, d + timedelta(days=1), f"Day: {args['day']}"
        except ValueError:
            pass
    if args.get("month"):
        try:
            d = datetime.strptime(args["month"] + "-01", "%Y-%m-%d").replace(tzinfo=timezone.utc)
            # naive +31 days then truncate to month end is fine for date range
            next_month = (d.replace(day=28) + timedelta(days=4)).replace(day=1)
            return d, next_month, f"Month: {args['month']}"
        except ValueError:
            pass
    try:
        n = max(1, min(int(args.get("days", "7")), 365))
    except ValueError:
        n = 7
    start = (now - timedelta(days=n)).replace(hour=0, minute=0, second=0, microsecond=0)
    return start, now + timedelta(seconds=1), f"Last {n} day(s)"


def _build_updates_pdf(emp, start, end, label, updates):
    """Build a well-aligned PDF report for a single employee."""
    from fpdf import FPDF

    class Report(FPDF):
        def header(self):
            # Logo + company name
            logo_path = os.path.join(app.root_path, "static", "images", "sugarrelax-logo.png")
            if os.path.exists(logo_path):
                try:
                    self.image(logo_path, x=10, y=8, w=18)
                except Exception:
                    pass
            self.set_font("Helvetica", "B", 16)
            self.set_text_color(26, 60, 110)
            self.set_xy(32, 10)
            self.cell(0, 7, "SUGAR.RELAX", ln=1)
            self.set_xy(32, 17)
            self.set_font("Helvetica", "", 9)
            self.set_text_color(120, 100, 150)
            self.cell(0, 5, "Cultivating Success Together", ln=1)
            self.set_draw_color(220, 227, 238)
            self.line(10, 28, 200, 28)
            self.ln(8)

        def footer(self):
            self.set_y(-15)
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(120, 120, 120)
            self.cell(0, 8, f"Page {self.page_no()}  -  Generated {fmt_ist(datetime.now(timezone.utc), '%Y-%m-%d %I:%M %p')} IST", align="C")

    pdf = Report(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    # Employee info block
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(30, 45, 64)
    pdf.cell(0, 8, "Work Updates Report", ln=1)
    pdf.ln(2)

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(80, 90, 110)
    info = [
        ("Employee", emp.get("display_name", "")),
        ("Username", "@" + emp.get("username", "")),
        ("Email", emp.get("email", "")),
        ("Range", label),
        ("Updates", str(len(updates))),
    ]
    for label_, value in info:
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(28, 6, label_ + ":", border=0)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, value, ln=1)
    pdf.ln(4)

    # Table header
    pdf.set_fill_color(240, 244, 251)
    pdf.set_text_color(30, 45, 64)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(40, 8, "Date / Time", border=0, fill=True)
    pdf.cell(0, 8, "Work Update", border=0, ln=1, fill=True)

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(40, 50, 70)
    if not updates:
        pdf.ln(4)
        pdf.set_text_color(150, 150, 150)
        pdf.cell(0, 8, "No updates in this range.", ln=1, align="C")
    for u in updates:
        when = fmt_ist(u["date"]) if u.get("date") else ""
        text = u.get("work_update", "")
        tags = []
        if u.get("admin_added"): tags.append("[admin-added]")
        if u.get("edited_by_admin"): tags.append("[admin-edited]")
        if tags: text = " ".join(tags) + " " + text

        # Date cell + multi-line wrapped text cell, aligned at the top of each row
        start_y = pdf.get_y()
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(40, 6, when, border=0)
        pdf.set_font("Helvetica", "", 10)
        x_text = pdf.get_x()
        pdf.multi_cell(0, 5.5, text)
        end_y = pdf.get_y()
        # subtle separator line
        pdf.set_draw_color(232, 237, 246)
        pdf.line(10, end_y + 1, 200, end_y + 1)
        pdf.ln(2)

    return bytes(pdf.output(dest="S"))


@app.route("/admin/download-updates-pdf/<employee_id>")
@admin_required
def download_updates_pdf(employee_id):
    from bson import ObjectId
    try:
        emp = employees_col.find_one({"_id": ObjectId(employee_id)})
    except Exception:
        emp = None
    if not emp:
        abort(404)

    start, end, label = _resolve_range(request.args)
    cur = updates_col.find({
        "employee_id": employee_id,
        "date": {"$gte": start, "$lt": end},
    }).sort("date", 1)
    rows = list(cur)

    pdf_bytes = _build_updates_pdf(emp, start, end, label, rows)
    fname = f"updates_{emp.get('username','employee')}_{start.strftime('%Y%m%d')}_to_{end.strftime('%Y%m%d')}.pdf"
    return Response(
        pdf_bytes, mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={fname}"},
    )


# ---- Update exports -------------------------------------------------------

def _updates_to_csv(rows):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Date", "Username", "Display Name", "Work Update"])
    for u in rows:
        d = fmt_ist(u["date"]) if u.get("date") else ""
        w.writerow([d, u.get("username", ""), u.get("display_name", ""),
                    u.get("work_update", "")])
    return buf.getvalue()


@app.route("/admin/download-updates/<employee_id>")
@admin_required
def download_updates_one(employee_id):
    from bson import ObjectId
    rows = list(updates_col.find({"employee_id": employee_id}).sort("date", -1))
    # Look up username from employees_col — not updates_col — so the filename
    # is correct even when the employee has no updates yet.
    try:
        emp = employees_col.find_one({"_id": ObjectId(employee_id)})
    except Exception:
        emp = None
    uname = emp.get("username", "employee") if emp else "employee"
    csv_data = _updates_to_csv(rows)
    return Response(
        csv_data, mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=updates_{uname}.csv"},
    )


@app.route("/admin/download-updates-all")
@admin_required
def download_updates_all():
    """Bundle one CSV per employee into a single zip."""
    mem = io.BytesIO()
    with zipfile.ZipFile(mem, "w", zipfile.ZIP_DEFLATED) as zf:
        for e in employees_col.find():
            eid = str(e["_id"])
            rows = list(updates_col.find({"employee_id": eid}).sort("date", -1))
            if not rows:
                continue
            zf.writestr(f"updates_{e.get('username', eid)}.csv", _updates_to_csv(rows))
        # Also a combined file with everyone's updates.
        all_rows = list(updates_col.find().sort("date", -1))
        zf.writestr("ALL_updates.csv", _updates_to_csv(all_rows))
    mem.seek(0)
    return Response(
        mem.getvalue(), mimetype="application/zip",
        headers={"Content-Disposition": "attachment; filename=all_employee_updates.zip"},
    )


# =========================================================================
# ERROR PAGES (don't leak stack traces)
# =========================================================================

@app.errorhandler(400)
def err_400(e):
    return render_template("error.html", code=400,
                           msg="Bad request."), 400


@app.errorhandler(403)
def err_403(e):
    return render_template("error.html", code=403,
                           msg="Access denied. This activity has been logged."), 403


@app.errorhandler(404)
def err_404(e):
    return render_template("error.html", code=404,
                           msg="Page not found."), 404


@app.errorhandler(500)
def err_500(e):
    return render_template("error.html", code=500,
                           msg="Something went wrong."), 500


if __name__ == "__main__":
    # debug=False  -> no interactive debugger / no stack traces to clients.
    app.run(host="0.0.0.0", port=5000, debug=False)
