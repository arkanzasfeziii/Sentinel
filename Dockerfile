FROM python:3.12-slim

LABEL maintainer="arkanzasfeziii"
LABEL description="Sentinel — Offensive Web & API Attack Framework"

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sentinel/ sentinel/

ENTRYPOINT ["python", "-m", "sentinel"]
CMD ["--help"]
