# TriNetra — universal log pre-processing framework.
# Multi-stage image: python (pipeline + API) + node (dashboard build).
# Just the backend + built dashboard, served by FastAPI static files.

# ---------------------------------------------------------------- api image
FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Base runtime deps (numpy/networkx are optional — pure-Python pipeline works
# without them; networkx powers Module C when present).
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt || \
    pip install --no-cache-dir fastapi uvicorn pyyaml requests

COPY . .

# ------------------------------------------------------------- dashboard build
FROM node:20-slim AS ui

WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY frontend/ .
RUN npm run build

# Final image: only the assembled service + dist/ assets.
FROM runtime AS final
COPY --from=ui /ui/dist /app/frontend/dist

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')" || exit 1

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]