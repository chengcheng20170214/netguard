FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y nmap masscan fping libcap2-bin && rm -rf /var/lib/apt/lists/*
RUN setcap cap_net_raw+ep /usr/bin/nmap && setcap cap_net_raw+ep /usr/bin/masscan
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -m -s /bin/bash appuser && chown -R appuser:appuser /app
USER appuser
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
