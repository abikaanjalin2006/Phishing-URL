from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3

app = Flask(__name__)
app.secret_key = "phishing_secret"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ---------- DATABASE ----------
def get_db():
    return sqlite3.connect("database.db")

def init_db():
    db = get_db()
    cur = db.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        url TEXT,
        result TEXT
    )
    """)

    db.commit()
    db.close()

# ---------- USER ----------
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, username FROM users WHERE id=?", (user_id,))
    user = cur.fetchone()
    db.close()
    if user:
        return User(user[0], user[1])
    return None

# ---------- PHISHING LOGIC ----------
def check_phishing(url):
    suspicious = ["@", "-", "//", ".exe", "http://"]
    score = 0
    for s in suspicious:
        if s in url:
            score += 1
    return "Phishing" if score >= 2 else "Safe"

# ---------- ROUTES ----------
@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        db = get_db()
        cur = db.cursor()
        try:
            cur.execute("INSERT INTO users(username,password) VALUES (?,?)",
                        (username, password))
            db.commit()
            flash("Account created successfully")
            return redirect(url_for("login"))
        except:
            flash("Username already exists")
        db.close()
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT id, username FROM users WHERE username=? AND password=?",
                    (username, password))
        user = cur.fetchone()
        db.close()

        if user:
            login_user(User(user[0], user[1]))
            return redirect(url_for("dashboard"))
        flash("Invalid login")
    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route("/check", methods=["GET", "POST"])
@login_required
def check():
    result = None
    if request.method == "POST":
        url = request.form["url"]
        result = check_phishing(url)

        db = get_db()
        cur = db.cursor()
        cur.execute("INSERT INTO history(user_id,url,result) VALUES (?,?,?)",
                    (current_user.id, url, result))
        db.commit()
        db.close()

    return render_template("check_url.html", result=result)

@app.route("/history")
@login_required
def history():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT url, result FROM history WHERE user_id=?",
                (current_user.id,))
    data = cur.fetchall()
    db.close()
    return render_template("history.html", data=data)

@app.route("/analytics")
@login_required
def analytics():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT result, COUNT(*) FROM history GROUP BY result")
    stats = cur.fetchall()
    db.close()
    return render_template("analytics.html", stats=stats)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)