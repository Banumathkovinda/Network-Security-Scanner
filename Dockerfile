FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p data/scans

ENV PORT=8080
EXPOSE 8080

CMD ["python", "simple_scanner.py"]
