@echo off
chcp 65001 > nul
title Worker Client (Esterno) - Distributed BTC Search

echo Impostazioni del Worker Client Esterno
echo =======================================

set /p THREADS="Inserisci il numero di thread da utilizzare [default: 4]: "
if "%THREADS%"=="" set THREADS=4

set /p BATCH_SIZE="Inserisci il batch-size da utilizzare [default: 100]: "
if "%BATCH_SIZE%"=="" set BATCH_SIZE=100

echo.
echo Avvio del Worker Client connesso a desktop-casa-giuse sulla porta 8085...
echo Thread: %THREADS% | Batch Size: %BATCH_SIZE%
echo =======================================
echo.

python worker_client.py --server desktop-casa-giuse --port 8085 --threads %THREADS% --batch-size %BATCH_SIZE%

echo.
pause
