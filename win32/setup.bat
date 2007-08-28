set DIR=%PROGRAMFILES%\Cntlm
if not exist "%DIR%" md "%DIR%"
copy /Y cntlm.exe "%DIR%"
if not exist "%DIR%\cntlm.ini" copy /Y cntlm.ini "%DIR%"
copy /Y cygrunsrv.exe "%DIR%"
copy /Y cygwin1.dll "%DIR%"
copy /Y uninstall.bat "%DIR%"
"%DIR%\cygrunsrv.exe" -R cntlm 2>NUL
"%DIR%\cygrunsrv.exe" -I cntlm -s KILL -t auto -p "%DIR%\cntlm.exe" -d "Cntlm Authentication Proxy" -f "HTTP Accelerator" -a "-f"
pause
