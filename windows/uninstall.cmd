@echo off
rem Double-click to remove ClaudeGuard and lift all blocks.
if exist "%ProgramFiles%\ClaudeGuard\claudeguard.exe" (
  copy /y "%ProgramFiles%\ClaudeGuard\claudeguard.exe" "%TEMP%\claudeguard-uninstall.exe" >nul
  "%TEMP%\claudeguard-uninstall.exe" uninstall
) else (
  cd /d "%~dp0"
  claudeguard.exe uninstall
)
echo.
pause
