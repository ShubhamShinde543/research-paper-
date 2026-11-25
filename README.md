# spdf-harness

A small test harness for measuring **Static-Pass Dynamic-Fail (SPDF)** and scanner "laundering" in LLM-assisted repair of
Flask and PHP web applications. It accompanies the paper *Scanner-Clean, Still Exploitable? A Pilot Study of Static-Pass
Dynamic-Fail Drift in LLM-Assisted Repair of Flask Web Applications* (Shinde, Tagadpallewar, Pare).

## What it does
For one application file it (1) starts the app in an isolated process with a temporary SQLite database, (2) runs nine
SQL-injection and XSS exploit tests and nine functional tests against a fixed interface contract, (3) runs the static gate
(Semgrep, plus Bandit for Python), and (4) reports whether the app is **SPDF** (scanner-clean for CWE-89/79 yet exploitable).
`harness/status.py` compares two rounds and labels each exploitable instance **Fixed, Persisting, Laundered, Blind,
Broken or Introduced**.

## Quick start
```
sh scripts/setup.sh                      # installs flask, semgrep, bandit, clones semgrep-rules
sh scripts/validate_references.sh        # oracle check on the four reference apps
python harness/evaluate.py path/to/app.py out.json     # or index.php
python harness/status.py round0.json round1.json
```
Needs Python 3.10+, and PHP 8 with PDO SQLite for PHP apps.

## Layout
- `contract/` interface contracts (Flask, PHP). Every app must follow one so the same tests run on all apps.
- `harness/tests.py` exploit and functional tests. Feedback exploits: `SQLI_LOGIN_USER, SQLI_SEARCH_OR, XSS_COMMENT_SCRIPT`.
  Held-out exploits (never shown to the repair model): `SQLI_LOGIN_PASS, SQLI_LOGIN_USER_OR, SQLI_SEARCH_COMMENT, XSS_COMMENT_IMG, XSS_SEARCH_REFLECT, XSS_TITLE`.
- `harness/scan.py` Semgrep and Bandit wrapper. `harness/evaluate.py` runner. `harness/status.py` status taxonomy.
- `refs/` hand-written vulnerable and secure reference apps (Flask and PHP) used to validate the oracles.
- `prompts/prompts.md` prompt templates for the generation and the C1 to C4 repair conditions.

## Important notes (please read)
- **This is a re-implementation.** The paper's pilot ran on an earlier version of this harness. Those working files were
  lost, so this repository was rebuilt from the same design (same contract, exploit classes, held-out split and taxonomy)
  and validated on the reference apps. Exact exploit payload strings and rule-set versions may differ from the pilot, and the
  pilot's raw per-application outputs are **not** included. The pilot numbers are reported in Table 2 of the paper only.
- Pilot tool versions: Semgrep 1.181.0 with semgrep-rules commit 17e31e1, Bandit 1.9.4. This repository clones the current
  semgrep-rules; pin a commit for reproducible scans.
- The scanner can flag safe code and miss unsafe code; the reference apps show a false positive (secure apps still get CWE-79/259 findings).
- The vulnerable reference apps are intentionally insecure. Run them only locally and never expose them to a network.

## License
MIT (see `LICENSE`).
