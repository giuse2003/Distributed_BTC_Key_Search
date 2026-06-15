@echo off
chcp 65001 > nul
title Worker Client (Remoto) - Distributed BTC Search
echo Avvio del Worker Client connesso a desktop-casa-giuse...
python worker_client.py --server desktop-casa-giuse --port 8085 --threads 8 --batch-size 20
echo.
pause
