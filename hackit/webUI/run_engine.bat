@echo off
title HackIT OSINT Engine (Python Edition)
cd %~dp0python
echo [+] Installing/Updating Dependencies...
pip install -r requirements.txt
echo [+] Starting Industrial Modular Python OSINT Engine...
python main.py
pause
