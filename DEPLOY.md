# Deploy Flask Task Manager

## Option A: Railway (recommended)
1. Push this project to GitHub.
2. In Railway, click **New Project** -> **Deploy from GitHub repo** and choose this repo.
3. Open the service -> **Variables** and add:
   - `SECRET_KEY` = any long random string
4. Add a PostgreSQL service in the same Railway project.
5. In app service variables, set:
   - `DATABASE_URL=${{Postgres.DATABASE_URL}}`
6. Railway auto-builds from `requirements.txt` and starts `gunicorn app:app`.
7. Open the generated Railway domain.

Notes:
- `app.py` normalizes `postgres://` to `postgresql://` for SQLAlchemy compatibility.
- Tables are auto-created on startup.

## Option B: Render
1. Push this project to GitHub.
2. In Render, create a **Blueprint** and point it to the repo.
3. Render will detect `render.yaml` and create the web service + persistent disk.
4. After deploy, open the generated URL.

## Option C: Generic VM / local server
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
gunicorn app:app -b 0.0.0.0:8000
```
Then place Nginx/Caddy in front if needed.
