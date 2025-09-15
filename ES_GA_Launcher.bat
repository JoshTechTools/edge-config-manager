```
:: File Name: ES_GA_Launcher.bat
:: Author: Joshua Bishop - developer01@joshspace.com
:: Date: 2025-09-14
:: Version: 1.0.5
:: Description: Launcher for EdgeSettings_GuestAccount.ps1 to configure Microsoft Edge 
::              with restrictive settings for standard user accounts used as guest accounts. 
::              Bypasses PowerShell execution policy and provides user-friendly prompts. 
::              No administrator privileges required as settings use HKCU.
::              Checks write access to HKEY_CURRENT_USER\SOFTWARE\Policies.

@echo off
setlocal enabledelayedexpansion
title Edge Settings Guest Account Launcher

:start
echo.
echo This will run EdgeSettings_GuestAccount.ps1 to configure Microsoft Edge settings.
echo No administrator privileges are required.
echo Checking write access to HKEY_CURRENT_USER\SOFTWARE\Policies...
echo.

:: Check registry write access
powershell -Command "try { New-Item -Path HKCU:\SOFTWARE\Policies -Name TestWriteAccess_$(Get-Date -Format yyyyMMddHHmmss) -ErrorAction Stop | Out-Null; Remove-Item -Path HKCU:\SOFTWARE\Policies\TestWriteAccess_* -ErrorAction Stop; exit 0 } catch { exit 1 }" >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Error: No write access to HKEY_CURRENT_USER\SOFTWARE\Policies.
    echo Run ES_Per_Launcher.bat to grant permissions or use the following as an admin:
    echo   powershell -Command "$acl = Get-Acl -Path HKCU:\SOFTWARE\Policies; $rule = New-Object System.Security.AccessControl.RegistryAccessRule('%username%', 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'); $acl.SetAccessRule($rule); Set-Acl -Path HKCU:\SOFTWARE\Policies -AclObject $acl"
    echo.
    echo Press any key to close...
    pause >nul
    exit /b 1
)

echo Write access confirmed.
echo Press any key to continue...
pause >nul

:runscript
echo.
echo Starting EdgeSettings_GuestAccount.ps1...
echo.

:: Check if PowerShell script exists
if not exist "%~dp0EdgeSettings_GuestAccount.ps1" (
    echo Error: EdgeSettings_GuestAccount.ps1 not found in the same directory.
    echo Please ensure the PowerShell script is in the same folder as this launcher.
    echo.
    echo Press any key to close...
    pause >nul
    exit /b 1
)

:: Run the PowerShell script
powershell -ExecutionPolicy Bypass -File "%~dp0EdgeSettings_GuestAccount.ps1"

echo.
echo Script execution completed.
echo Press any key to close...
pause >nul
exit /b 0
```