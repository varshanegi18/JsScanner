FROM python:3.11-slim

WORKDIR /app

# Install dependencies — no requirements.txt needed
RUN pip install --no-cache-dir flask==3.0.3 gunicorn==22.0.0

# Copy application files
COPY scanner.py .
COPY app.py .

# Non-root user for security
RUN addgroup --system --gid 1001 scanner && \
    adduser --system --uid 1001 --gid 1001 scanner

USER scanner

EXPOSE 8000

# Gunicorn with gthread workers — required for SSE streaming
CMD ["gunicorn", \
     "--bind",         "0.0.0.0:8000", \
     "--workers",      "4", \
     "--worker-class", "gthread", \
     "--threads",      "8", \
     "--timeout",      "600", \
     "--keep-alive",   "65", \
     "app:app"]