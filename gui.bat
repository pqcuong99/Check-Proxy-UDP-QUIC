@echo off
rem Mo giao dien ProxyCheck (tu mo cua so trinh duyet). Dong cua so de thoat.
cd /d "%~dp0"
node gui.js
if errorlevel 1 pause
