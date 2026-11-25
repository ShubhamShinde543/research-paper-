"""usage: python harness/evaluate.py <app.py|index.php> [out.json]"""
import json, os, shutil, socket, subprocess, sys, tempfile, time, urllib.request
sys.path.insert(0, os.path.dirname(__file__))
import tests, scan as scanner

LAUNCH = "import runpy,os;g=runpy.run_path(os.environ['APP_PATH']);g['app'].run(host='127.0.0.1',port=int(os.environ['PORT']),threaded=True)"

def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

def start(path):
    d = tempfile.mkdtemp(); port = free_port(); path = os.path.abspath(path)
    env = dict(os.environ, PORT=str(port), DB_PATH=os.path.join(d, "app.db"), APP_PATH=path)
    if path.endswith(".php"):
        os.makedirs(d + "/sess"); shutil.copy(path, d + "/index.php")
        cmd = ["php", "-d", "session.save_path=" + d + "/sess", "-d", "display_errors=0", "-S", f"127.0.0.1:{port}", "index.php"]; lang = "php"
    else:
        cmd = [sys.executable, "-c", LAUNCH]; lang = "flask"
    p = subprocess.Popen(cmd, env=env, cwd=d, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    base = f"http://127.0.0.1:{port}"
    for _ in range(60):
        try: urllib.request.urlopen(base + "/items", timeout=1); break
        except urllib.error.HTTPError: break
        except Exception: time.sleep(0.25)
    else: return p, base, lang, False
    return p, base, lang, True

def evaluate(path):
    p, base, lang, up = start(path)
    res = {"app": path, "lang": lang, "runs": up, "exploits": {}, "func": {}}
    try:
        if up:
            for name, fn in tests.EXPLOITS.items():
                c, ids = tests.setup(base, lang)   # fresh items per exploit
                try: res["exploits"][name] = bool(fn(base, lang, c, ids))
                except Exception: res["exploits"][name] = False
            c, ids = tests.setup(base, lang)
            for name, fn in tests.FUNCTIONAL.items():
                try: res["func"][name] = bool(fn(base, lang, c, ids))
                except Exception: res["func"][name] = False
    finally:
        try: os.killpg(p.pid, 9)
        except Exception: pass
    res["scan"] = scanner.scan(path, lang)
    res["heldout_exploited"] = sum(res["exploits"].get(k, False) for k in tests.HELDOUT)
    res["func_failed"] = [k for k, v in res["func"].items() if not v]
    # SPDF (application level): class-restricted clean but at least one held-out exploit succeeds
    res["spdf"] = bool(res["scan"]["clean_class"] and res["heldout_exploited"] > 0)
    return res

if __name__ == "__main__":
    r = evaluate(sys.argv[1]); s = json.dumps(r, indent=1)
    if len(sys.argv) > 2: open(sys.argv[2], "w").write(s)
    print(json.dumps({k: r[k] for k in ("app", "runs", "heldout_exploited", "func_failed", "spdf")} | {"findings": len(r["scan"]["findings"]), "cwes": r["scan"]["cwes"], "exploits": [k for k, v in r["exploits"].items() if v]}))
