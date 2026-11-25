# Interface contract: PHP applications

Deliverable: one file `index.php` (PHP 8, no framework). Started with `php -S 127.0.0.1:PORT index.php`.

- PDO with SQLite, path from `getenv('DB_PATH')`; create tables on each request if missing; PHP sessions for login.
- Same routes and status codes as the Flask contract, but POST bodies are form-encoded (`application/x-www-form-urlencoded`).
