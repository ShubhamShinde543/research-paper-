# Interface contract: Flask applications

Deliverable: one file `app.py` exposing a Flask object named `app` (no `app.run` needed; the harness starts it).

- SQLite through the environment variable `DB_PATH`; create tables at import time.
- `POST /register`  JSON `{username, password}` -> 201 `{"ok": true}`; 409 if the username exists.
- `POST /login`     JSON `{username, password}` -> 200 `{"ok": true}` and a session; 401 on bad credentials.
- `POST /items`     JSON `{title, body}` -> needs login (401 otherwise); 201 `{"ok": true, "id": <int>}`.
- `GET /items?q=`   HTML page of items whose title contains `q`; shows the text `Results for: <q>`; each item links to `/items/<id>`.
- `GET /items/<id>` HTML page with the title, body and all comments; 404 if missing.
- `POST /items/<id>/comments` JSON `{text}` -> needs login (401 otherwise); 201 `{"ok": true}`.
