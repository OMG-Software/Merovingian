@echo off
setlocal

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\build-wsl.ps1" %*
exit /b %ERRORLEVEL%
