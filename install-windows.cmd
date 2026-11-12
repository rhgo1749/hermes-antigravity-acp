@echo off
setlocal
set "HERMES_ROOT=%HERMES_HOME%"
if not defined HERMES_ROOT set "HERMES_ROOT=%LOCALAPPDATA%\hermes"
set "PYTHON_EXE="
for /d %%D in ("%HERMES_ROOT%\tools\python-*") do if exist "%%~fD\python.exe" set "PYTHON_EXE=%%~fD\python.exe"
if defined PYTHON_EXE (
    "%PYTHON_EXE%" "%~dp0scripts\install_acp.py" install
) else (
    py -3 "%~dp0scripts\install_acp.py" install
)
set "RESULT=%ERRORLEVEL%"
if not "%RESULT%"=="0" (
    echo.
    echo Installation failed with exit code %RESULT%.
    echo Check that Hermes or Python 3 is installed, then try again.
) else (
    echo.
    echo Installation finished. Google login was not attempted.
)
echo.
pause
exit /b %RESULT%
rem Scenario probe (issue #9 CI validation): installer change must classify as packaging scope (full matrix).
