#!/bin/bash
cd /home/wanjj/code/netguard/backend
exec .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
