:: File Name: ES_Per_Launcher.bat
:: Author: Joshua Bishop - developer01@joshspace.com
:: Date: 2025-09-14
:: Version: 1.0.2
:: Description: Launcher for EdgeSettings_Permissions.ps1 to manage registry permissions 
::              for HKEY_CURRENT_USER\SOFTWARE\Policies for user NowGuest. Provides options 
::              to grant FullControl, restore restricted permissions, or exit. Bypasses 
::              PowerShell execution policy and provides user-friendly prompts. Requires 
::              administrator privileges for permission changes.

@echo off
setlocal enabledelayedexpansion
title Edge Settings Permissions Manager

:start
echo.
echo This will run EdgeSettings_Permissions.ps1 to manage registry permissions for NowGuest.
echo Administrator privileges are required for permission changes.
echo Press any key to continue...
pause >nul

:: Check if we're already running as admin
net session >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo Administrator privileges confirmed.
    goto runscript
)

:: Request elevation
powershell -Command "Start-Process cmd -ArgumentList '/c \"%~f0\" admin' -Verb RunAs" 2>nul
if %ERRORLEVEL% neq 0 goto elevationfailed

:: Exit original process after launching elevated instance
if "%1" neq "admin" exit /b 0

:runscript
echo.
echo Starting EdgeSettings_Permissions.ps1 for user NowGuest...
echo.

:: Check if PowerShell script exists
if not exist "%~dp0EdgeSettings_Permissions.ps1" (
    echo Error: EdgeSettings_Permissions.ps1 not found in the same directory.
    echo Please ensure the PowerShell script is in the same folder as this launcher.
    echo.
    echo Press any key to close...
    pause >nul
    exit /b 1
)

:: Run the PowerShell script with the target user set to NowGuest
powershell -ExecutionPolicy Bypass -File "%~dp0EdgeSettings_Permissions.ps1" -TargetUser "NowGuest"

echo.
echo Script execution completed.
echo Press any key to close...
pause >nul
exit /b 0

:elevationfailed
echo.
echo Error: Administrator elevation failed. Try again? (1=Retry, 2=Exit)
set /p choice="Enter 1 or 2: "
if "!choice!"=="1" goto start
if "!choice!"=="2" (
    echo.
    echo No changes were made. Press any key to close.
    pause >nul
    exit /b 1
)
echo.
echo Invalid selection. Press any key to close.
pause >nul
exit /b 1