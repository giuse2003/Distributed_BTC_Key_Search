@echo off
chcp 65001 > nul
title Server Coordinator - Distributed BTC Search
echo Avvio del Server Coordinator...
py server_coordinator.py
echo.
pause
