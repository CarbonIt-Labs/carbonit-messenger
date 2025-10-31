@echo off
title CarbonIt Node Launcher
color 0a

:: Set working directory to the CarbonIt base folder
cd /d "%~dp0"

echo ==========================================
echo       ≡ƒºá CarbonIt Secure Messenger
echo ==========================================
echo.

:: Ask for user details
set /p username="Enter your username: "
set /p password="Enter your password: "

:: Generate public & private keys using Python
for /f "tokens=*" %%i in ('python -c "import sys; sys.path.append(r'%cd%'); from Keys.public_key_private_key.generate_keys import generate_keys; priv, pub = generate_keys('%username%', '%password%'); print(pub)"') do set publickey=%%i

echo.
echo Your CarbonIt Public ID (Share this with your contact):
echo ------------------------------------------
echo %publickey%
echo ------------------------------------------
echo.

set /p peer_public="Enter peer's public key (hashed username): "
set /p peer_ip="Enter peer's IP address: "
set /p peer_port="Enter peer's port (default 5050): "

if "%peer_port%"=="" set peer_port=5050
if "%peer_ip%"=="" set peer_ip=127.0.0.1

echo.
echo Starting CarbonIt node...
echo ------------------------------------------

:: Move into the network folder before running Python
cd /d "%~dp0network"

python carbonit_node.py %username% %password% %peer_public% %peer_ip% %peer_port%

echo ------------------------------------------
echo [NODE EXITED]
pause
