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
    wsl --install
    echo.
    echo ✅ WSL features enabled. Please restart your computer to complete setup and run the script again.
    pause
    exit /b
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
    echo and save it as "%INSTALLER_NAME%" in your Downloads folder then try again.
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
:: === CHECK DOCKER RUNNING ===
echo Checking if Docker is running...
set /a MAX_RETRIES=10
set /a RETRY_COUNT=0

:: Check if Docker CLI is in PATH
where docker >nul 2>&1
if %errorlevel% neq 0 (
    echo Docker command not found in PATH. Trying to refresh environment...
    :: Try to find Docker installation
    if exist "C:\Program Files\Docker\Docker\resources\bin\docker.exe" (
        echo Found Docker at default location. Adding to PATH for this session...
        set "PATH=%PATH%;C:\Program Files\Docker\Docker\resources\bin"
    )
    )

:waitloop
docker info >nul 2>&1
if %errorlevel% equ 0 (
    echo Docker is running.
    goto DOCKER_RUNNING
)
set /a RETRY_COUNT+=1
if %RETRY_COUNT% geq %MAX_RETRIES% (
    echo Docker appears to be taking too long to start.
    echo If Docker Desktop is already running, press any key to continue anyway.
    pause >nul
    goto CHECK_DOCKER_RUNNING_CONTINUE
)
echo Waiting for Docker to start... Attempt %RETRY_COUNT% of %MAX_RETRIES%
timeout /t 5 >nul
goto waitloop

:CHECK_DOCKER_RUNNING_CONTINUE
echo.
echo ⚠️ Warning: Docker might not be running correctly, but we'll try to continue.
echo If you encounter errors, please ensure Docker Desktop is running.

:DOCKER_RUNNING
:: === RUN CONTAINER ===
echo Pulling and running your password manager...

:: Try to pull the image, with error handling
echo Pulling the container image...
docker pull vickm81/pass-man
if %errorlevel% neq 0 (
    echo.
    echo ❌ Failed to pull the container image. Please check that:
    echo   1. Docker Desktop is running
    echo   2. You have internet connectivity
    echo   3. The image name is correct
    echo.
    pause
    exit /b
)

:: Check if container already exists
docker ps -a | findstr password-manager >nul
if %errorlevel% equ 0 (
    echo Container already exists. Removing old container...
    docker rm -f password-manager >nul 2>&1
)

:: Run the container with error handling
echo Starting container...
docker run -d -p 5000:5000 --name password-manager vickm81/pass-man
if %errorlevel% neq 0 (
    echo.
    echo ❌ Failed to start the container. Please check that:
    echo   1. Port 5000 is not already in use
    echo   2. Docker has sufficient permissions
    echo   3. Docker Desktop is running correctly
    echo.
    pause
    exit /b
)
echo.
echo ✅ Your password manager is now running at: http://localhost:5000
pause
