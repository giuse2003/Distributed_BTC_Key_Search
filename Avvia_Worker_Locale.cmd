@echo off
chcp 65001 > nul
title Worker Client (Locale) - Distributed BTC Search
echo Avvio del Worker Client connesso a localhost...
python worker_client.py --server 127.0.0.1 --port 8000
echo.
pause
