"""Static gate: Semgrep (+ Bandit for Python). Rules come from a local clone of semgrep-rules (see scripts/setup.sh)."""
import json, os, re, subprocess
RULES = os.environ.get("SEMGREP_RULES", os.path.join(os.path.dirname(__file__), "..", "semgrep-rules"))
PY_CONFIGS = ["python/flask", "python/lang/security", "python/sqlalchemy"]
PHP_CONFIGS = ["php/lang/security"]

def _cwes(raw):
    raw = raw if isinstance(raw, list) else [raw]
    return sorted({int(m.group(1)) for x in raw for m in [re.search(r"CWE-(\d+)", str(x))] if m})

def semgrep(path, lang):
    cfgs = PY_CONFIGS if lang == "flask" else PHP_CONFIGS
    cmd = ["semgrep", "--metrics=off", "--disable-version-check", "--json", "--quiet"]
    for c in cfgs: cmd += ["--config", os.path.join(RULES, c)]
    p = subprocess.run(cmd + [path], capture_output=True, text=True, timeout=300)
    try: j = json.loads(p.stdout)
    except Exception: raise RuntimeError("semgrep failed: " + p.stderr[-400:])
    return [{"tool": "semgrep", "rule": r["check_id"].split(".")[-1], "line": r["start"]["line"],
             "cwe": _cwes(r["extra"].get("metadata", {}).get("cwe", [])), "msg": r["extra"]["message"][:200]}
            for r in j.get("results", [])]

def bandit(path):
    p = subprocess.run(["bandit", "-q", "-f", "json", path], capture_output=True, text=True, timeout=120)
    try: j = json.loads(p.stdout)
    except Exception: raise RuntimeError("bandit failed: " + p.stderr[-400:])
    out = []
    for r in j.get("results", []):
        c = r.get("issue_cwe", {}).get("id")
        out.append({"tool": "bandit", "rule": r["test_id"], "line": r["line_number"], "cwe": [c] if c else [], "msg": r["issue_text"][:200]})
    return out

def scan(path, lang):
    f = semgrep(path, lang) + (bandit(path) if lang == "flask" else [])
    cw = sorted({c for x in f for c in x["cwe"]})
    return {"findings": f, "cwes": cw, "vis_sqli": 89 in cw, "vis_xss": 79 in cw,
            "clean_class": not (89 in cw or 79 in cw), "clean_all": not f}
