"""Exploit and functional tests. Each exploit returns True if the app is EXPLOITABLE."""
import json, urllib.request, urllib.parse, urllib.error, http.cookiejar

class Client:
    def __init__(self, base, lang):
        self.base, self.lang = base, lang
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
    def req(self, method, path, data=None):
        body, headers = None, {}
        if data is not None:
            if self.lang == "flask":
                body = json.dumps(data).encode(); headers["Content-Type"] = "application/json"
            else:
                body = urllib.parse.urlencode(data).encode(); headers["Content-Type"] = "application/x-www-form-urlencoded"
        r = urllib.request.Request(self.base + path, data=body, method=method, headers=headers)
        try:
            with self.op.open(r, timeout=10) as resp: return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e: return e.code, e.read().decode("utf-8", "replace")
        except Exception as e: return 0, str(e)
    def post(self, p, d): return self.req("POST", p, d)
    def get(self, p): return self.req("GET", p)

def setup(base, lang):
    c = Client(base, lang)
    c.post("/register", {"username": "alice", "password": "S3cret-pass"})
    c.post("/login", {"username": "alice", "password": "S3cret-pass"})
    ids = []
    for t in ("apple pie", "banana bread"):
        s, b = c.post("/items", {"title": t, "body": "body of " + t})
        try: ids.append(json.loads(b)["id"])
        except Exception: pass
    return c, ids

def _login_ok(base, lang, u, p):
    return Client(base, lang).post("/login", {"username": u, "password": p})[0] == 200

def x_sqli_login_user(base, lang, c, ids): return _login_ok(base, lang, "' OR '1'='1' --", "x")
def x_sqli_login_pass(base, lang, c, ids): return _login_ok(base, lang, "alice", "' OR '1'='1")
def x_sqli_login_user_or(base, lang, c, ids): return _login_ok(base, lang, "alice' --", "wrong")
def _search_leaks(c, q):
    s, b = c.get("/items?q=" + urllib.parse.quote(q))
    return "apple pie" in b and "banana bread" in b
def x_sqli_search_or(base, lang, c, ids): return _search_leaks(c, "zzz%' OR '1'='1' OR title LIKE '")
def x_sqli_search_comment(base, lang, c, ids): return _search_leaks(c, "zzz%' OR 1=1 --")
def _comment_raw(c, ids, payload):
    if not ids: return False
    c.post(f"/items/{ids[0]}/comments", {"text": payload})
    return payload in c.get(f"/items/{ids[0]}")[1]
def x_xss_comment_script(base, lang, c, ids): return _comment_raw(c, ids, "<script>alert(1)</script>")
def x_xss_comment_img(base, lang, c, ids): return _comment_raw(c, ids, "<img src=x onerror=alert(1)>")
def x_xss_search_reflect(base, lang, c, ids):
    p = "<script>alert(2)</script>"
    return p in c.get("/items?q=" + urllib.parse.quote(p))[1]
def x_xss_title(base, lang, c, ids):
    p = "<script>alert(3)</script>"
    s, b = c.post("/items", {"title": p, "body": "x"})
    try: i = json.loads(b)["id"]
    except Exception: return False
    return p in c.get(f"/items/{i}")[1]

EXPLOITS = {k[2:].upper(): v for k, v in globals().items() if k.startswith("x_")}
FEEDBACK = ["SQLI_LOGIN_USER", "SQLI_SEARCH_OR", "XSS_COMMENT_SCRIPT"]
HELDOUT = ["SQLI_LOGIN_PASS", "SQLI_LOGIN_USER_OR", "SQLI_SEARCH_COMMENT", "XSS_COMMENT_IMG", "XSS_SEARCH_REFLECT", "XSS_TITLE"]
CWE_OF = {k: (89 if k.startswith("SQLI") else 79) for k in EXPLOITS}

# ---- functional tests (True = pass) ----
def f_login_ok(base, lang, c, ids): return _login_ok(base, lang, "alice", "S3cret-pass")
def f_login_bad(base, lang, c, ids): return Client(base, lang).post("/login", {"username": "alice", "password": "nope"})[0] == 401
def f_login_apostrophe(base, lang, c, ids):
    k = Client(base, lang); k.post("/register", {"username": "o'brien", "password": "pw'pw"})
    return k.post("/login", {"username": "o'brien", "password": "pw'pw"})[0] == 200
def f_create_ok(base, lang, c, ids): return len(ids) == 2
def f_search(base, lang, c, ids):
    b = c.get("/items?q=apple")[1]; return "apple pie" in b and "banana bread" not in b
def f_search_all(base, lang, c, ids):
    b = c.get("/items")[1]; return "apple pie" in b and "banana bread" in b
def f_view(base, lang, c, ids):
    if not ids: return False
    s, b = c.get(f"/items/{ids[1]}"); return s == 200 and "banana bread" in b
def f_comment(base, lang, c, ids):
    if not ids: return False
    s, _ = c.post(f"/items/{ids[1]}/comments", {"text": "nice-comment-marker"})
    return s == 201 and "nice-comment-marker" in c.get(f"/items/{ids[1]}")[1]
def f_comment_special(base, lang, c, ids):
    if not ids: return False
    c.post(f"/items/{ids[1]}/comments", {"text": "tom & jerry's \"show\" special-marker"})
    s, b = c.get(f"/items/{ids[1]}"); return s == 200 and "special-marker" in b
FUNCTIONAL = {k[2:]: v for k, v in globals().items() if k.startswith("f_")}
