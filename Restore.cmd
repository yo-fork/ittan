@echo off
setlocal
set "PSModulePath=%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Restore.ps1" %*
set "WMS_EXIT=%ERRORLEVEL%"
pause
exit /b %WMS_EXIT%
