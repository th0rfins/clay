FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY moclaw.py app.py ./
COPY templates ./templates
ENV MOCLAW_DIR=/data PYTHONUNBUFFERED=1
VOLUME /data
CMD sh -c "uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000}"
