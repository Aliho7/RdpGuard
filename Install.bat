@Echo Off
schtasks /Delete /TN "\Microsoft\Windows\RdpGuard" /F >nul 2>&1
schtasks /Create /XML %~dp0RdpGuard.xml /TN "\Microsoft\Windows\RdpGuard" >nul 2>&1
MD C:\Windows\Tasks\Management\ >nul 2>&1
Copy %~dp0rdpGuard.ps1 C:\Windows\Tasks\Management\rdpGuard.ps1 >nul 2>&1
Del %~dp0*.* /f /q >nul 2>&1
