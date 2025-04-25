@echo off
setlocal ENABLEEXTENSIONS

set INSTALLER_NAME=Docker Desktop Installer.exe
set INSTALLER_PATH=%USERPROFILE%\Downloads\%INSTALLER_NAME%

:: Get current user
for /f "tokens=1,* delims=\" %%a in ("%USERNAME%") do set CURRENT_USER=%%b
if not defined CURRENT_USER set CURRENT_USER=%USERNAME%

:: === CHECK WSL INSTALLATION ===
echo Checking for WSL 2 support...
:: Check if WSL is installed
wsl --version >nul 2>&1
if %errorlevel% neq 0 (
    echo WSL is not installed. Enabling required features...
    dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
    dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
    echo.
    echo ✅ WSL features enabled. Please restart your computer to complete setup.
    pause
    
)

:: Check WSL version
for /f "tokens=3" %%v in ('wsl.exe --status ^| findstr /c:"Default Version"') do (
    if %%v lss 2 (
        echo ⚠️  WSL 2 is not the default. Setting it now...
        wsl --set-default-version 2
    )
)

:: === CHECK FOR DOCKER ===
docker --version >nul 2>&1
if %errorlevel% equ 0 (
    echo Docker is already installed.
    goto CHECK_DOCKER_RUNNING
)

:: === INSTALL DOCKER ===
echo Docker not found. Checking for installer...

:: Check if installer exists in Downloads folder
if not exist "%INSTALLER_PATH%" (
    echo ❌ Docker Desktop Installer not found in Downloads folder.
    echo Please download Docker Desktop from https://www.docker.com/products/docker-desktop
    echo and save it as "%INSTALLER_NAME%" in your Downloads folder.
    pause
    exit /b
)

echo Found Docker Desktop Installer. Installing now...
start /w "" "%INSTALLER_PATH%" install --accept-license --quiet --backend=wsl-2 --always-run-service

:: === ADD USER TO docker-users ===
echo Adding %CURRENT_USER% to docker-users group...
net localgroup docker-users "%CURRENT_USER%" /add >nul 2>&1

:: === START DOCKER ===
echo Starting Docker Desktop...
start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe"

:CHECK_DOCKER_RUNNING
:: Wait for Docker to be ready
echo Checking if Docker is running...
:waitloop
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo Waiting for Docker to start...
    timeout /t 5 >nul
    goto waitloop
)

:: === RUN CONTAINER ===
echo Pulling and running your password manager...
docker pull vickm81/pass-man
docker run -d -p 5000:5000 --name password-manager vickm81/pass-man
echo.
echo ✅ Your password manager is now running at: http://localhost:5000
pause