#!/bin/sh
# Sanity check of the oracles: vulnerable references must be exploitable, secure references must not.
for a in refs/vuln_flask.py refs/secure_flask.py refs/vuln.php refs/secure.php; do echo "== $a"; python3 harness/evaluate.py $a; done
