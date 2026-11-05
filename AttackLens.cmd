@echo off
rem Starts AttackLens in this window. Press Ctrl+C here to stop everything.
title AttackLens
cd /d "%~dp0"
".venv\Scripts\attacklens.exe" start
pause
