"""
HCG Form - ระบบแบบฟอร์มออนไลน์
วิธีรัน:  pip install -r requirements.txt
          python app.py
เปิดเว็บ:  http://127.0.0.1:5000
"""
import io
import json
import os
import random
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template,
                   render_template_string, request, send_file, session, url_for)
from PIL import Image, ImageDraw, ImageFilter, ImageFont
from werkzeug.security import check_password_hash, generate_password_hash

# =====================================================================
# บัญชีผู้ดูแลระบบและแอดมิน (แก้อีเมลให้เป็นอีเมลจริงก่อนใช้งาน)
# แนะนำให้ตั้งค่าผ่าน Environment Variable แทนการเขียนไว้ในโค้ด
# =====================================================================
STAFF_ACCOUNTS = [
    {
        "username": os.environ.get("HCG_HQ_USERNAME", "headoffice"),
        "email": os.environ.get("HCG_HQ_EMAIL", "headoffice@hcgform.local"),
        "password": os.environ.get("HCG_HQ_PASSWORD", "AienasjshkJsowkbao238173"),
        "role": "superadmin",
    },
    {
        "username": os.environ.get("HCG_ADMIN_USERNAME", "admin"),
        "email": os.environ.get("HCG_ADMIN_EMAIL", "admin@hcgform.local"),
        "password": os.environ.get("HCG_ADMIN_PASSWORD", "Jsoahnwig27ueisbkaKsihs2882"),
        "role": "admin",
    },
]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "hcg.db")
TH_TZ = timezone(timedelta(hours=7), "Asia/Bangkok")
HISTORY_DAYS = 30

ROLE_LABELS = {"superadmin": "ผู้ดูแลระบบ (สำนักงานใหญ่)", "admin": "แอดมิน", "user": "ผู้ใช้งาน"}
STATUS_LABELS = {"pending": "กำลังรออนุมัติ", "approved": "อนุมัติ", "rejected": "ไม่อนุมัติ"}
QTYPE_LABELS = {"text": "แบบตอบคำถาม", "truefalse": "แบบแตะถูกผิด", "choice": "แบบเลือกตอบ"}
ACTION_LABELS = {
    "register": "สร้างบัญชี", "login": "เข้าสู่ระบบ", "logout": "ออกจากระบบ",
    "submit": "ส่งแบบฟอร์ม", "approve": "อนุมัติ", "reject": "ไม่อนุมัติ",
    "form_create": "สร้างแบบฟอร์ม", "form_delete": "ลบแบบฟอร์ม",
}
TF_OPTIONS = ("ถูก", "ผิด")
TH_MONTHS = ["ม.ค.", "ก.พ.", "มี.ค.", "เม.ย.", "พ.ค.", "มิ.ย.",
             "ก.ค.", "ส.ค.", "ก.ย.", "ต.ค.", "พ.ย.", "ธ.ค."]

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.]{4,20}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
URL_RE = re.compile(r"^https?://[^\s<>\"']+$", re.IGNORECASE)
CAPTCHA_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def load_secret_key():
    env_key = os.environ.get("HCG_SECRET_KEY")
    if env_key:
        return env_key
    path = os.path.join(BASE_DIR, "secret.key")
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            f.write(secrets.token_hex(32))
    with open(path, encoding="utf-8") as f:
        return f.read().strip()


app = Flask(__name__, template_folder=BASE_DIR, static_folder=None)
app.config.update(
    SECRET_KEY=load_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS forms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  created_by INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL,
  is_deleted INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS questions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  form_id INTEGER NOT NULL REFERENCES forms(id),
  position INTEGER NOT NULL,
  qtype TEXT NOT NULL,
  text TEXT NOT NULL,
  options TEXT NOT NULL DEFAULT '[]',
  required INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  form_id INTEGER NOT NULL REFERENCES forms(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  status TEXT NOT NULL DEFAULT 'pending',
  reason TEXT,
  link TEXT,
  reviewed_by INTEGER REFERENCES users(id),
  reviewed_at TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS answers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  submission_id INTEGER NOT NULL REFERENCES submissions(id),
  question_id INTEGER NOT NULL REFERENCES questions(id),
  value TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS activity (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id),
  target_id INTEGER REFERENCES users(id),
  action TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sub_user ON submissions(user_id);
CREATE INDEX IF NOT EXISTS idx_sub_form ON submissions(form_id);
CREATE INDEX IF NOT EXISTS idx_act_time ON activity(created_at);
"""


# ----------------------------- ฐานข้อมูล -----------------------------
def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def init_db():
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA)
    for acc in STAFF_ACCOUNTS:
        exists = con.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (acc["username"], acc["email"].lower()),
        ).fetchone()
        if not exists:
            con.execute(
                "INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?,?,?,?,?)",
                (acc["username"], acc["email"].lower(),
                 generate_password_hash(acc["password"]), acc["role"], utcnow()),
            )
    con.commit()
    con.close()


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def log(action, detail="", user_id=None, target_id=None):
    get_db().execute(
        "INSERT INTO activity (user_id, target_id, action, detail, created_at) VALUES (?,?,?,?,?)",
        (user_id, target_id, action, detail, utcnow()),
    )


# ----------------------------- เวลาไทย -----------------------------
def to_th(iso):
    return datetime.fromisoformat(iso).astimezone(TH_TZ)


def fmt_date(d):
    return f"{d.day} {TH_MONTHS[d.month - 1]} {d.year + 543}"


@app.template_filter("thtime")
def thtime(iso):
    if not iso:
        return "-"
    dt = to_th(iso)
    return f"{fmt_date(dt)} {dt:%H:%M} น."


@app.template_filter("thclock")
def thclock(iso):
    return f"{to_th(iso):%H:%M} น." if iso else "-"


def last_days():
    today = datetime.now(TH_TZ).date()
    return [today - timedelta(days=i) for i in range(HISTORY_DAYS - 1, -1, -1)]


def since_iso():
    start = datetime.combine(last_days()[0], datetime.min.time(), TH_TZ)
    return start.astimezone(timezone.utc).isoformat(timespec="seconds")


# ----------------------------- ความปลอดภัย -----------------------------
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


def is_staff(user):
    return bool(user) and user["role"] in ("superadmin", "admin")


@app.before_request
def load_user_and_check_csrf():
    g.user = None
    uid = session.get("uid")
    if uid:
        g.user = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        if g.user is None:
            session.clear()
    if request.method == "POST":
        token = request.form.get("_csrf", "")
        if not token or not secrets.compare_digest(token, session.get("_csrf", "")):
            abort(400)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            flash("กรุณาเข้าสู่ระบบก่อน", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def staff_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            flash("กรุณาเข้าสู่ระบบก่อน", "error")
            return redirect(url_for("login"))
        if not is_staff(g.user):
            abort(403)
        return view(*args, **kwargs)
    return wrapped


@app.context_processor
def inject_helpers():
    user = g.get("user")
    staff = is_staff(user)
    pending = 0
    if staff:
        pending = get_db().execute(
            "SELECT COUNT(*) FROM submissions WHERE status = 'pending'").fetchone()[0]
    return {
        "csrf_token": csrf_token,
        "staff": staff,
        "pending_count": pending,
        "role_label": lambda r: ROLE_LABELS.get(r, r),
        "status_label": lambda s: STATUS_LABELS.get(s, s),
        "qtype_label": lambda q: QTYPE_LABELS.get(q, q),
        "action_label": lambda a: ACTION_LABELS.get(a, a),
    }


# ----------------------------- ไฟล์ CSS -----------------------------
@app.route("/style.css")
def stylesheet():
    return send_file(os.path.join(BASE_DIR, "style.css"), mimetype="text/css", max_age=0)


# ----------------------------- รูปรหัสยืนยัน -----------------------------
@app.route("/captcha.png")
def captcha():
    code = "".join(random.choices(CAPTCHA_CHARS, k=5))
    session["captcha"] = code
    width, height = 210, 70
    img = Image.new("RGB", (width, height), (244, 239, 255))
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.load_default(size=40)
    except TypeError:
        font = ImageFont.load_default()

    for _ in range(7):
        draw.line(
            [(random.randint(0, width), random.randint(0, height)),
             (random.randint(0, width), random.randint(0, height))],
            fill=(random.randint(170, 210), random.randint(150, 200), 240),
            width=2,
        )
    x = 14
    for ch in code:
        layer = Image.new("RGBA", (48, 64), (0, 0, 0, 0))
        ImageDraw.Draw(layer).text(
            (8, 6), ch, font=font,
            fill=(random.randint(70, 120), random.randint(40, 80), random.randint(150, 210), 255),
        )
        layer = layer.rotate(random.randint(-28, 28), resample=Image.BICUBIC)
        img.paste(layer, (x, random.randint(-2, 8)), layer)
        x += 38
    for _ in range(260):
        draw.point((random.randint(0, width - 1), random.randint(0, height - 1)),
                   fill=(random.randint(120, 200), random.randint(100, 180), 230))
    img = img.filter(ImageFilter.SMOOTH)

    buf = io.BytesIO()
    img.save(buf, "PNG")
    buf.seek(0)
    resp = send_file(buf, mimetype="image/png")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return resp


# ----------------------------- บัญชีผู้ใช้ -----------------------------
@app.route("/")
def index():
    if not g.user:
        return redirect(url_for("login"))
    return redirect(url_for("admin_dashboard" if is_staff(g.user) else "home"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("index"))
    login_type = request.form.get("login_type", "username")
    if login_type not in ("username", "email"):
        login_type = "username"
    identifier = ""
    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")
        column = "email" if login_type == "email" else "username"
        user = get_db().execute(
            f"SELECT * FROM users WHERE {column} = ?", (identifier,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["uid"] = user["id"]
            session.permanent = True
            log("login", "เข้าสู่ระบบด้วย" + ("อีเมล" if column == "email" else "ชื่อไอดี"), user["id"])
            get_db().commit()
            return redirect(url_for("index"))
        flash("ชื่อไอดี อีเมล หรือรหัสผ่านไม่ถูกต้อง", "error")
    return render_template("login.html", login_type=login_type, identifier=identifier)


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("index"))
    form = {"username": "", "email": ""}
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        code = request.form.get("captcha", "").strip().upper()
        expected = session.pop("captcha", None)
        form = {"username": username, "email": email}

        errors = []
        if not expected or code != expected:
            errors.append("รหัสจากรูปภาพไม่ถูกต้อง กรุณาลองใหม่")
        if not USERNAME_RE.match(username):
            errors.append("ชื่อไอดีต้องยาว 4-20 ตัว ใช้ได้เฉพาะ a-z, A-Z, 0-9, จุด และขีดล่าง")
        if not EMAIL_RE.match(email):
            errors.append("รูปแบบอีเมลไม่ถูกต้อง")
        if len(password) < 8 or not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
            errors.append("รหัสผ่านต้องยาวอย่างน้อย 8 ตัว และมีทั้งตัวอักษรและตัวเลข")
        if password != confirm:
            errors.append("รหัสผ่านทั้งสองช่องไม่ตรงกัน")

        db = get_db()
        if not errors:
            if db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
                errors.append("ชื่อไอดีนี้ถูกใช้งานแล้ว")
            if db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
                errors.append("อีเมลนี้ถูกใช้งานแล้ว")

        if errors:
            for e in errors:
                flash(e, "error")
        else:
            cur = db.execute(
                "INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?,?,?,?,?)",
                (username, email, generate_password_hash(password), "user", utcnow()),
            )
            log("register", f"สร้างบัญชี {username}", cur.lastrowid)
            db.commit()
            flash("สร้างบัญชีสำเร็จ กรุณาเข้าสู่ระบบ", "success")
            return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route("/logout", methods=["POST"])
def logout():
    if g.user:
        log("logout", "ออกจากระบบ", g.user["id"])
        get_db().commit()
    session.clear()
    flash("ออกจากระบบเรียบร้อย", "success")
    return redirect(url_for("login"))


# ----------------------------- ฝั่งผู้ใช้งาน -----------------------------
def load_questions(form_id):
    rows = get_db().execute(
        "SELECT * FROM questions WHERE form_id = ? ORDER BY position", (form_id,)).fetchall()
    result = []
    for r in rows:
        item = dict(r)
        item["options"] = json.loads(r["options"] or "[]")
        result.append(item)
    return result


def latest_submission(form_id, user_id):
    return get_db().execute(
        "SELECT * FROM submissions WHERE form_id = ? AND user_id = ? ORDER BY id DESC LIMIT 1",
        (form_id, user_id)).fetchone()


@app.route("/home")
@login_required
def home():
    if is_staff(g.user):
        return redirect(url_for("admin_dashboard"))
    db = get_db()
    forms = db.execute(
        "SELECT * FROM forms WHERE is_deleted = 0 ORDER BY id DESC").fetchall()
    latest = {}
    for row in db.execute(
            "SELECT * FROM submissions WHERE user_id = ? ORDER BY id DESC", (g.user["id"],)):
        latest.setdefault(row["form_id"], row)
    return render_template("home.html", forms=forms, latest=latest)


@app.route("/history")
@login_required
def history():
    if is_staff(g.user):
        return redirect(url_for("admin_submissions"))
    rows = get_db().execute(
        """SELECT s.*, f.title, f.is_deleted FROM submissions s
           JOIN forms f ON f.id = s.form_id
           WHERE s.user_id = ? ORDER BY s.id DESC""", (g.user["id"],)).fetchall()
    return render_template("history.html", rows=rows)


@app.route("/form/<int:form_id>", methods=["GET", "POST"])
@login_required
def fill_form(form_id):
    if is_staff(g.user):
        return redirect(url_for("admin_forms"))
    db = get_db()
    form = db.execute(
        "SELECT * FROM forms WHERE id = ? AND is_deleted = 0", (form_id,)).fetchone()
    if not form:
        abort(404)
    last = latest_submission(form_id, g.user["id"])
    if last and last["status"] in ("pending", "approved"):
        flash("คุณส่งแบบฟอร์มนี้แล้ว ไม่สามารถแก้ไขได้", "info")
        return redirect(url_for("view_submission", sid=last["id"]))

    questions = load_questions(form_id)
    values = {}
    if request.method == "POST":
        values = request.form
        answers, missing = {}, []
        for idx, q in enumerate(questions, 1):
            val = request.form.get(f"q_{q['id']}", "").strip()[:5000]
            if q["qtype"] == "choice" and val not in q["options"]:
                val = ""
            if q["qtype"] == "truefalse" and val not in TF_OPTIONS:
                val = ""
            if q["required"] and not val:
                missing.append(str(idx))
            answers[q["id"]] = val
        if missing:
            flash("กรุณาตอบคำถามที่จำเป็นให้ครบ: ข้อ " + ", ".join(missing), "error")
        else:
            cur = db.execute(
                "INSERT INTO submissions (form_id, user_id, status, created_at) VALUES (?,?,?,?)",
                (form_id, g.user["id"], "pending", utcnow()))
            sid = cur.lastrowid
            for qid, val in answers.items():
                db.execute(
                    "INSERT INTO answers (submission_id, question_id, value) VALUES (?,?,?)",
                    (sid, qid, val))
            log("submit", f"ส่งแบบฟอร์ม {form['title']}", g.user["id"])
            db.commit()
            flash("ส่งแบบฟอร์มเรียบร้อย กำลังรออนุมัติ", "success")
            return redirect(url_for("view_submission", sid=sid))
    return render_template("fill_form.html", form=form, questions=questions,
                           values=values, tf_options=TF_OPTIONS, resubmit=bool(last))


def get_submission(sid):
    row = get_db().execute(
        """SELECT s.*, f.title, f.description, f.is_deleted,
                  u.username, u.email, r.username AS reviewer
           FROM submissions s
           JOIN forms f ON f.id = s.form_id
           JOIN users u ON u.id = s.user_id
           LEFT JOIN users r ON r.id = s.reviewed_by
           WHERE s.id = ?""", (sid,)).fetchone()
    if not row:
        abort(404)
    return row


def get_items(sub):
    return get_db().execute(
        """SELECT q.id, q.qtype, q.text, a.value FROM questions q
           LEFT JOIN answers a ON a.question_id = q.id AND a.submission_id = ?
           WHERE q.form_id = ? ORDER BY q.position""",
        (sub["id"], sub["form_id"])).fetchall()


@app.route("/submission/<int:sid>")
@login_required
def view_submission(sid):
    if is_staff(g.user):
        return redirect(url_for("admin_review", sid=sid))
    sub = get_submission(sid)
    if sub["user_id"] != g.user["id"]:
        abort(403)
    last = latest_submission(sub["form_id"], g.user["id"])
    can_resubmit = (sub["status"] == "rejected" and not sub["is_deleted"]
                    and last is not None and last["id"] == sub["id"])
    return render_template("submission.html", sub=sub, items=get_items(sub),
                           review=False, can_resubmit=can_resubmit)


# ----------------------------- ฝั่งผู้ดูแล -----------------------------
@app.route("/admin")
@staff_required
def admin_dashboard():
    db = get_db()

    def scalar(sql, *params):
        return db.execute(sql, params).fetchone()[0]

    latest_cte = """WITH latest AS (
        SELECT s.* FROM submissions s
        WHERE s.id = (SELECT MAX(s2.id) FROM submissions s2
                      WHERE s2.user_id = s.user_id AND s2.form_id = s.form_id))"""
    stats = {
        "users": scalar("SELECT COUNT(*) FROM users WHERE role = 'user'"),
        "approved": scalar(latest_cte + " SELECT COUNT(DISTINCT user_id) FROM latest WHERE status = 'approved'"),
        "rejected": scalar(latest_cte + " SELECT COUNT(DISTINCT user_id) FROM latest WHERE status = 'rejected'"),
        "pending": scalar(latest_cte + " SELECT COUNT(DISTINCT user_id) FROM latest WHERE status = 'pending'"),
        "forms": scalar("SELECT COUNT(*) FROM forms WHERE is_deleted = 0"),
    }

    since = since_iso()
    buckets = {d: {"label": fmt_date(d), "short": f"{d.day}/{d.month}",
                   "reg": 0, "sub": 0, "app": 0, "rej": 0} for d in last_days()}

    def add(iso, key):
        d = to_th(iso).date()
        if d in buckets:
            buckets[d][key] += 1

    for r in db.execute("SELECT created_at FROM users WHERE role = 'user' AND created_at >= ?", (since,)):
        add(r[0], "reg")
    for r in db.execute("SELECT created_at FROM submissions WHERE created_at >= ?", (since,)):
        add(r[0], "sub")
    for r in db.execute(
            "SELECT status, reviewed_at FROM submissions WHERE reviewed_at >= ? "
            "AND status IN ('approved', 'rejected')", (since,)):
        add(r["reviewed_at"], "app" if r["status"] == "approved" else "rej")

    days = list(buckets.values())
    peak = max([d["reg"] + d["sub"] for d in days] + [1])
    for d in days:
        d["h_reg"] = round(d["reg"] / peak * 100, 1)
        d["h_sub"] = round(d["sub"] / peak * 100, 1)
    totals = {k: sum(d[k] for d in days) for k in ("reg", "sub", "app", "rej")}
    active_days = [d for d in reversed(days) if d["reg"] or d["sub"] or d["app"] or d["rej"]]

    recent = db.execute(
        """SELECT a.*, u.username AS actor, t.username AS target FROM activity a
           LEFT JOIN users u ON u.id = a.user_id
           LEFT JOIN users t ON t.id = a.target_id
           ORDER BY a.id DESC LIMIT 8""").fetchall()
    return render_template("admin_dashboard.html", stats=stats, days=days,
                           totals=totals, active_days=active_days, recent=recent)


@app.route("/admin/forms")
@staff_required
def admin_forms():
    forms = get_db().execute(
        """SELECT f.*, u.username AS creator,
                  (SELECT COUNT(*) FROM questions q WHERE q.form_id = f.id) AS qcount,
                  (SELECT COUNT(*) FROM submissions s WHERE s.form_id = f.id) AS scount,
                  (SELECT COUNT(*) FROM submissions s WHERE s.form_id = f.id AND s.status = 'pending') AS pcount
           FROM forms f LEFT JOIN users u ON u.id = f.created_by
           WHERE f.is_deleted = 0 ORDER BY f.id DESC""").fetchall()
    return render_template("admin_forms.html", forms=forms)


@app.route("/admin/forms/new", methods=["GET", "POST"])
@staff_required
def admin_form_new():
    payload, form_title, form_desc = [], "", ""
    if request.method == "POST":
        form_title = request.form.get("title", "").strip()[:200]
        form_desc = request.form.get("description", "").strip()[:2000]
        try:
            raw = json.loads(request.form.get("payload") or "[]")
        except ValueError:
            raw = []
        if not isinstance(raw, list):
            raw = []

        errors, questions = [], []
        if not form_title:
            errors.append("กรุณาตั้งชื่อแบบฟอร์ม")
        if not raw:
            errors.append("กรุณาเพิ่มคำถามอย่างน้อย 1 ข้อ")
        for i, item in enumerate(raw, 1):
            if not isinstance(item, dict) or item.get("type") not in QTYPE_LABELS:
                errors.append(f"ข้อ {i}: ประเภทคำถามไม่ถูกต้อง")
                continue
            qtype = item["type"]
            text = str(item.get("text", "")).strip()[:1000]
            options = []
            if not text:
                errors.append(f"ข้อ {i}: กรุณาพิมพ์คำถาม")
            if qtype == "choice":
                for o in item.get("options") or []:
                    o = str(o).strip()[:300]
                    if o and o not in options:
                        options.append(o)
                if len(options) < 2:
                    errors.append(f"ข้อ {i}: แบบเลือกตอบต้องมีอย่างน้อย 2 ตัวเลือก")
            questions.append({"type": qtype, "text": text,
                              "required": bool(item.get("required")), "options": options})

        if errors:
            for e in errors:
                flash(e, "error")
            payload = questions
        else:
            db = get_db()
            cur = db.execute(
                "INSERT INTO forms (title, description, created_by, created_at) VALUES (?,?,?,?)",
                (form_title, form_desc, g.user["id"], utcnow()))
            fid = cur.lastrowid
            for pos, q in enumerate(questions):
                db.execute(
                    "INSERT INTO questions (form_id, position, qtype, text, options, required) "
                    "VALUES (?,?,?,?,?,?)",
                    (fid, pos, q["type"], q["text"],
                     json.dumps(q["options"], ensure_ascii=False), int(q["required"])))
            log("form_create", f"สร้างแบบฟอร์ม {form_title}", g.user["id"])
            db.commit()
            flash("สร้างแบบฟอร์มเรียบร้อย", "success")
            return redirect(url_for("admin_forms"))
    return render_template("admin_form_new.html", payload=payload,
                           form_title=form_title, form_desc=form_desc)


@app.route("/admin/forms/<int:form_id>/delete", methods=["POST"])
@staff_required
def admin_form_delete(form_id):
    db = get_db()
    form = db.execute("SELECT * FROM forms WHERE id = ? AND is_deleted = 0", (form_id,)).fetchone()
    if not form:
        abort(404)
    db.execute("UPDATE forms SET is_deleted = 1 WHERE id = ?", (form_id,))
    log("form_delete", f"ลบแบบฟอร์ม {form['title']}", g.user["id"])
    db.commit()
    flash("ลบแบบฟอร์มเรียบร้อย", "success")
    return redirect(url_for("admin_forms"))


@app.route("/admin/submissions")
@staff_required
def admin_submissions():
    db = get_db()
    status = request.args.get("status", "pending")
    if status not in ("pending", "approved", "rejected", "all"):
        status = "pending"
    form_id = request.args.get("form", type=int)

    where, params = [], []
    if form_id:
        where.append("s.form_id = ?")
        params.append(form_id)
    base_where = " AND ".join(where)

    counts = {"all": 0, "pending": 0, "approved": 0, "rejected": 0}
    for r in db.execute(
            "SELECT s.status, COUNT(*) FROM submissions s"
            + (" WHERE " + base_where if base_where else "") + " GROUP BY s.status", params):
        counts[r[0]] = r[1]
        counts["all"] += r[1]

    if status != "all":
        where.append("s.status = ?")
        params.append(status)
    rows = db.execute(
        """SELECT s.*, f.title, u.username, u.email FROM submissions s
           JOIN forms f ON f.id = s.form_id JOIN users u ON u.id = s.user_id"""
        + (" WHERE " + " AND ".join(where) if where else "")
        + " ORDER BY s.id DESC", params).fetchall()
    form = db.execute("SELECT * FROM forms WHERE id = ?", (form_id,)).fetchone() if form_id else None
    return render_template("admin_submissions.html", rows=rows, status=status,
                           counts=counts, form=form, form_id=form_id)


@app.route("/admin/submissions/<int:sid>", methods=["GET", "POST"])
@staff_required
def admin_review(sid):
    sub = get_submission(sid)
    if request.method == "POST":
        db = get_db()
        action = request.form.get("action")
        if action == "approve":
            link = request.form.get("link", "").strip()[:1000]
            if not URL_RE.match(link):
                flash("กรุณาใส่ลิงก์ที่ขึ้นต้นด้วย http:// หรือ https://", "error")
            else:
                db.execute(
                    "UPDATE submissions SET status = 'approved', link = ?, reason = NULL, "
                    "reviewed_by = ?, reviewed_at = ? WHERE id = ?",
                    (link, g.user["id"], utcnow(), sid))
                log("approve", f"อนุมัติแบบฟอร์ม {sub['title']} ของ {sub['username']}",
                    g.user["id"], sub["user_id"])
                db.commit()
                flash("อนุมัติและส่งลิงก์เรียบร้อย", "success")
        elif action == "reject":
            reason = request.form.get("reason", "").strip()[:2000]
            if not reason:
                flash("กรุณาพิมพ์ปัญหาที่ไม่อนุมัติ", "error")
            else:
                db.execute(
                    "UPDATE submissions SET status = 'rejected', reason = ?, link = NULL, "
                    "reviewed_by = ?, reviewed_at = ? WHERE id = ?",
                    (reason, g.user["id"], utcnow(), sid))
                log("reject", f"ไม่อนุมัติแบบฟอร์ม {sub['title']} ของ {sub['username']}",
                    g.user["id"], sub["user_id"])
                db.commit()
                flash("บันทึกผลไม่อนุมัติเรียบร้อย", "success")
        return redirect(url_for("admin_review", sid=sid))
    return render_template("submission.html", sub=sub, items=get_items(sub),
                           review=True, can_resubmit=False)


@app.route("/admin/timeline")
@staff_required
def admin_timeline():
    db = get_db()
    uid = request.args.get("user", type=int)
    sql = """SELECT a.*, u.username AS actor, u.role AS actor_role, t.username AS target
             FROM activity a
             LEFT JOIN users u ON u.id = a.user_id
             LEFT JOIN users t ON t.id = a.target_id
             WHERE a.created_at >= ?"""
    params = [since_iso()]
    if uid:
        sql += " AND (a.user_id = ? OR a.target_id = ?)"
        params += [uid, uid]
    sql += " ORDER BY a.id DESC LIMIT 1000"

    groups = []
    for r in db.execute(sql, params):
        d = to_th(r["created_at"]).date()
        if not groups or groups[-1]["date"] != d:
            groups.append({"date": d, "label": fmt_date(d), "items": []})
        groups[-1]["items"].append(r)
    users = db.execute("SELECT id, username, role FROM users ORDER BY username").fetchall()
    return render_template("admin_timeline.html", groups=groups, users=users, uid=uid)


# ----------------------------- หน้าข้อผิดพลาด -----------------------------
ERROR_PAGE = """{% extends "base.html" %}
{% block title %}{{ code }}{% endblock %}
{% block content %}
<section class="glass card error-card">
  <p class="eyebrow">ข้อผิดพลาด {{ code }}</p>
  <h1>{{ message }}</h1>
  <a class="btn primary" href="{{ url_for('index') }}">กลับหน้าหลัก</a>
</section>
{% endblock %}"""

ERROR_MESSAGES = {
    400: "คำขอไม่ถูกต้อง กรุณารีเฟรชหน้าแล้วลองใหม่",
    403: "คุณไม่มีสิทธิ์เข้าถึงหน้านี้",
    404: "ไม่พบหน้าที่ต้องการ",
    413: "ข้อมูลมีขนาดใหญ่เกินไป",
}


def error_handler(code):
    def handler(_e):
        return render_template_string(ERROR_PAGE, code=code, message=ERROR_MESSAGES[code]), code
    return handler


for _code in ERROR_MESSAGES:
    app.register_error_handler(_code, error_handler(_code))


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)