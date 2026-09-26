@echo off
copy /Y "%~dp0sig-net.lua" "C:\Users\wayne\AppData\Roaming\Wireshark\Plugins\"
if %errorlevel% == 0 (
    echo Installed sig-net.lua successfully.
) else (
    echo ERROR: Copy failed.
)
pause
