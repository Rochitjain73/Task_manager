# Deploy Flask Task Manager

## Option A: Render (recommended for this repo)
1. Push this project to GitHub.
2. In Render, create a **Blueprint** and point it to the repo.
3. Render will detect `render.yaml` and create the web service + persistent disk.
4. After deploy, open the generated URL.

Required env vars are already defined in `render.yaml`:
- `SECRET_KEY` (auto-generated)
- `DATABASE_URL` (uses mounted disk at `/var/data/task_manager.db`)

## Option B: Generic VM / local server
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
gunicorn app:app -b 0.0.0.0:8000
```
Then place Nginx/Caddy in front if needed.
