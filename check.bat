@echo off
rem Chay: check.bat proxies.txt   (hoac keo-tha file danh sach vao file nay)
cd /d "%~dp0"
if "%~1"=="" (
  node proxycheck.js -f proxies.txt -v -o ketqua.csv --good udp_ok.txt --good-quic quic_ok.txt
) else (
  node proxycheck.js -f "%~1" -v -o ketqua.csv --good udp_ok.txt --good-quic quic_ok.txt
)
pause
