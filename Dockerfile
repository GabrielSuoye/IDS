FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
  libpcap-dev \
  gcc \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/ 

ENV IDS_INTERFACE="eth0"

CMD ["python", "-u", "src/monitor.py"]
