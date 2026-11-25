#!/bin/sh
set -e
pip install flask semgrep bandit
[ -d semgrep-rules ] || git clone --depth 1 https://github.com/semgrep/semgrep-rules semgrep-rules
command -v php >/dev/null || echo "Install PHP 8 with the sqlite/pdo extension to test PHP apps"
