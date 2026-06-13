@echo off
chcp 65001 > nul
title Server Coordinator - Distributed BTC Search
echo Avvio del Server Coordinator...
python server_coordinator.py
echo.
pause
