import os, sqlite3
from flask import Flask, request, jsonify, session
from markupsafe import escape
from werkzeug.security import generate_password_hash, check_password_hash
app = Flask(__name__); app.secret_key = "dev"
DB = os.environ.get("DB_PATH", "app.db")
def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c
with db() as c:
    c.executescript("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT);"
                    "CREATE TABLE IF NOT EXISTS items(id INTEGER PRIMARY KEY, title TEXT, body TEXT);"
                    "CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY, item_id INTEGER, text TEXT);")
@app.post("/register")
def register():
    d = request.get_json(force=True)
    try:
        with db() as c: c.execute("INSERT INTO users(username,password) VALUES(?,?)", (d["username"], generate_password_hash(d["password"])))
    except sqlite3.IntegrityError: return jsonify(ok=False), 409
    return jsonify(ok=True), 201
@app.post("/login")
def login():
    d = request.get_json(force=True)
    r = db().execute("SELECT * FROM users WHERE username=?", (d["username"],)).fetchone()
    if r and check_password_hash(r["password"], d["password"]): session["u"] = r["username"]; return jsonify(ok=True)
    return jsonify(ok=False), 401
@app.post("/items")
def create():
    if "u" not in session: return jsonify(ok=False), 401
    d = request.get_json(force=True)
    with db() as c: cur = c.execute("INSERT INTO items(title,body) VALUES(?,?)", (d["title"], d["body"]))
    return jsonify(ok=True, id=cur.lastrowid), 201
@app.get("/items")
def items():
    q = request.args.get("q", "")
    rows = db().execute("SELECT * FROM items WHERE title LIKE ?", ("%" + q + "%",)).fetchall()
    return "<h1>Results for: %s</h1>" % escape(q) + "".join("<a href='/items/%d'>%s</a><br>" % (r["id"], escape(r["title"])) for r in rows)
@app.get("/items/<int:i>")
def view(i):
    r = db().execute("SELECT * FROM items WHERE id=?", (i,)).fetchone()
    if not r: return "not found", 404
    cs = db().execute("SELECT text FROM comments WHERE item_id=?", (i,)).fetchall()
    return "<h1>%s</h1><p>%s</p>" % (escape(r["title"]), escape(r["body"])) + "".join("<div>%s</div>" % escape(c["text"]) for c in cs)
@app.post("/items/<int:i>/comments")
def comment(i):
    if "u" not in session: return jsonify(ok=False), 401
    with db() as c: c.execute("INSERT INTO comments(item_id,text) VALUES(?,?)", (i, request.get_json(force=True)["text"]))
    return jsonify(ok=True), 201
