# EdgeSettings_Permissions_WinUtil.ps1
# Microsoft Edge Registry Permissions Manager - WinUtil-Aligned Version

<#
.SYNOPSIS
    Manages registry permissions for Microsoft Edge policies using WinUtil-aligned patterns
.DESCRIPTION
    Uses Registry:: provider syntax exclusively to avoid PSDrive complexities. Based on proven
    patterns from ChrisTitusTech/winutil for reliable Windows registry operations.
.AUTHOR
    Based on WinUtil architecture patterns and proven registry approaches
.VERSION
    4.0.0
.DATE
    2025-09-14
.NOTES
    Production-ready version using WinUtil-aligned approach:
    - Registry:: provider syntax exclusively
    - No PSDrive creation or management
    - Simplified error handling with graceful failures
    - Direct registry operations following WinUtil patterns
    Requires administrator privileges to modify permissions.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$TargetUser = $env:USERNAME
)

# Global variables - simplified WinUtil style
$script:LogFiles = @{}
$script:ScriptStartTime = Get-Date
$script:EdgePolicyPath = "SOFTWARE\Policies\Microsoft\Edge"
$script:TempHiveName = "EdgePermTempHive"
$script:UserSid = $null
$script:HiveLoaded = $false

# Proven SID pattern
$script:PatternSID = 'S-1-5-21-\d+-\d+\-\d+\-\d+$'

$Colors = @{
    Title = "Cyan"; Info = "White"; Success = "Green"
    Warning = "Yellow"; Error = "Red"; Menu = "Yellow"; Input = "Magenta"
}

#region Logging Functions
function Initialize-LogFiles {
    try {
        $timestamp = Get-Date -Format "yyyyMMddHHmmss"
        $scriptDir = if ($MyInvocation.ScriptName) { Split-Path -Parent $MyInvocation.ScriptName } else { $PWD.Path }
        $script:LogFiles = @{ Activity = Join-Path $scriptDir ("EdgePermLog_" + $timestamp + ".txt") }
        Write-LogEntry "INFO" "=== Edge Permissions Manager (WinUtil-Aligned) Started ==="
        Write-LogEntry "INFO" "Target user: $TargetUser"
    }
    catch { Write-Warning "Failed to initialize logging: $($_.Exception.Message)" }
}

function Write-LogEntry {
    param(
        [Parameter(Mandatory=$true)][ValidateSet("DEBUG", "INFO", "WARN", "ERROR", "CRITICAL")][string]$Level,
        [Parameter(Mandatory=$true)][string]$Message
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    try {
        if ($script:LogFiles.Activity) {
            Add-Content -Path $script:LogFiles.Activity -Value $logEntry -ErrorAction SilentlyContinue
        }
    }
    catch { }
    
    if ($Level -in @("ERROR", "CRITICAL")) { Write-Host $logEntry -ForegroundColor Red }
    elseif ($Level -eq "WARN") { Write-Host $logEntry -ForegroundColor Yellow }
}
#endregion

#region Security and Validation Functions
function Test-AdminPrivileges {
    try {
        $currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}

function Test-UserInput {
    param([string]$Username)
    if ($Username -match '[<>:"/\\|?*]' -or [string]::IsNullOrWhiteSpace($Username)) {
        throw "Invalid username format"
    }
    return $true
}
#endregion

#region SID Resolution - WinUtil style simplified
function Get-UserSid {
    param([string]$TargetUser)
    
    Write-LogEntry "DEBUG" "Getting SID for user: $TargetUser"
    
    try {
        # Method 1: Direct translation (most reliable)
        try {
            $user = New-Object System.Security.Principal.NTAccount($TargetUser)
            $sid = $user.Translate([System.Security.Principal.SecurityIdentifier]).Value
            if ($sid -match $script:PatternSID) {
                Write-LogEntry "DEBUG" "SID resolved: $sid"
                return $sid
            }
        }
        catch { Write-LogEntry "DEBUG" "Direct SID translation failed" }
        
        # Method 2: Registry profile lookup
        try {
            $profileList = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' -ErrorAction Stop | 
                          Where-Object {$_.PSChildName -match $script:PatternSID} |
                          Where-Object {$_.ProfileImagePath -like "*\$TargetUser"}
            
            if ($profileList) {
                $sid = $profileList[0].PSChildName
                if ($sid -match $script:PatternSID) {
                    Write-LogEntry "DEBUG" "SID resolved via registry: $sid"
                    return $sid
                }
            }
        }
        catch { Write-LogEntry "DEBUG" "Registry profile lookup failed" }
        
        throw "Could not resolve SID for user '$TargetUser'"
    }
    catch {
        Write-LogEntry "ERROR" "SID resolution failed: $($_.Exception.Message)"
        throw
    }
}
#endregion

#region Registry Operations - WinUtil Registry:: Pattern
function Test-UserCurrentlyLoggedIn {
    param([string]$TargetUser)
    
    try {
        $explorerProcess = Get-Process -Name explorer -IncludeUserName -ErrorAction Stop | Select-Object -First 1
        if ($explorerProcess -and $explorerProcess.UserName) {
            $currentUsername = $explorerProcess.UserName.Split('\')[-1]
            return ($currentUsername -eq $TargetUser)
        }
        return $false
    }
    catch { return $false }
}

function Get-RegistryPath {
    param([string]$TargetUser)
    
    if (Test-UserCurrentlyLoggedIn -TargetUser $TargetUser) {
        # User is logged in, use HKCU
        return "HKCU:\$script:EdgePolicyPath"
    }
    else {
        # User not logged in, use loaded hive with Registry:: syntax
        return "Registry::HKEY_USERS\$script:TempHiveName\$script:EdgePolicyPath"
    }
}

function Load-UserHive {
    param([string]$TargetUser)
    
    Write-LogEntry "INFO" "Loading registry hive for user: $TargetUser"
    
    try {
        # Validate NTUSER.DAT file
        $ntuserPath = "C:\Users\$TargetUser\NTUSER.DAT"
        if (-not (Test-Path $ntuserPath)) {
            throw "NTUSER.DAT not found at '$ntuserPath'"
        }
        
        # Clean up any existing hive
        reg unload "HKU\$script:TempHiveName" 2>$null
        
        # Load the hive using reg.exe
        Write-LogEntry "DEBUG" "Loading hive: reg load HKU\$script:TempHiveName `"$ntuserPath`""
        $loadResult = reg load "HKU\$script:TempHiveName" "`"$ntuserPath`"" 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to load registry hive. Exit code: $LASTEXITCODE, Output: $loadResult"
        }
        
        # Verify hive accessibility using Registry:: syntax
        $testPath = "Registry::HKEY_USERS\$script:TempHiveName"
        if (-not (Test-Path $testPath)) {
            throw "Hive loaded but not accessible via Registry:: provider"
        }
        
        Write-LogEntry "INFO" "Successfully loaded registry hive"
        $script:HiveLoaded = $true
        return $true
    }
    catch {
        Write-LogEntry "ERROR" "Failed to load registry hive: $($_.Exception.Message)"
        return $false
    }
}

function Unload-UserHive {
    if (-not $script:HiveLoaded) { return $true }
    
    Write-LogEntry "DEBUG" "Unloading registry hive"
    
    try {
        # Simple garbage collection
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
        
        # Unload hive
        $unloadResult = reg unload "HKU\$script:TempHiveName" 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-LogEntry "INFO" "Successfully unloaded registry hive"
            $script:HiveLoaded = $false
            return $true
        }
        else {
            Write-LogEntry "WARN" "Unload failed: $unloadResult"
            return $false
        }
    }
    catch {
        Write-LogEntry "ERROR" "Exception during hive unload: $($_.Exception.Message)"
        return $false
    }
}

function New-RegistryAccessRule {
    param(
        [string]$User,
        [System.Security.AccessControl.RegistryRights]$Rights
    )
    
    # WinUtil-style simple rule creation
    $userAccount = [System.Security.Principal.NTAccount]$User
    $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    $accessType = [System.Security.AccessControl.AccessControlType]::Allow
    
    return New-Object System.Security.AccessControl.RegistryAccessRule(
        $userAccount, $Rights, $inheritance, $propagation, $accessType
    )
}
#endregion

#region Permission Functions - Registry:: Pattern
function Grant-FullControl {
    Write-Host "`nGranting FullControl to '$TargetUser'..." -ForegroundColor $Colors.Info
    Write-LogEntry "INFO" "Granting FullControl to '$TargetUser'"
    
    if (-not (Test-AdminPrivileges)) {
        Write-Host "Administrator privileges required" -ForegroundColor $Colors.Error
        return $false
    }
    
    try {
        $needsHiveLoad = -not (Test-UserCurrentlyLoggedIn -TargetUser $TargetUser)
        
        if ($needsHiveLoad) {
            if (-not (Load-UserHive -TargetUser $TargetUser)) {
                throw "Failed to load registry hive"
            }
        }
        
        # Get registry path using Registry:: syntax
        $regPath = Get-RegistryPath -TargetUser $TargetUser
        Write-LogEntry "DEBUG" "Using registry path: $regPath"
        
        # Ensure Edge policy key exists
        if (-not (Test-Path $regPath)) {
            Write-LogEntry "INFO" "Creating Edge policy path"
            New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
        }
        
        # Apply permissions using Registry:: path
        $acl = Get-Acl -Path $regPath -ErrorAction Stop
        $rule = New-RegistryAccessRule -User $TargetUser -Rights ([System.Security.AccessControl.RegistryRights]::FullControl)
        $acl.SetAccessRule($rule)
        Set-Acl -Path $regPath -AclObject $acl -ErrorAction Stop
        
        # Validate permissions were applied
        $newAcl = Get-Acl -Path $regPath
        $userHasFullControl = $newAcl.Access | Where-Object { 
            $_.IdentityReference -like "*$TargetUser" -and 
            $_.RegistryRights -match "FullControl" -and 
            $_.AccessControlType -eq "Allow" 
        }
        
        if ($userHasFullControl) {
            Write-LogEntry "INFO" "Successfully granted and validated FullControl"
            Write-Host "Successfully granted FullControl to '$TargetUser'" -ForegroundColor $Colors.Success
            $result = $true
        }
        else {
            Write-LogEntry "ERROR" "Permission validation failed"
            Write-Host "Permission grant validation failed" -ForegroundColor $Colors.Warning
            $result = $false
        }
        
        if ($needsHiveLoad) { Unload-UserHive }
        return $result
    }
    catch {
        Write-LogEntry "ERROR" "Failed to grant FullControl: $($_.Exception.Message)"
        Write-Host "Failed to grant FullControl: $($_.Exception.Message)" -ForegroundColor $Colors.Error
        if ($needsHiveLoad) { Unload-UserHive }
        return $false
    }
}

function Restore-RestrictedPermissions {
    Write-Host "`nRestoring restricted permissions for '$TargetUser'..." -ForegroundColor $Colors.Info
    Write-LogEntry "INFO" "Restoring restricted permissions for '$TargetUser'"
    
    if (-not (Test-AdminPrivileges)) {
        Write-Host "Administrator privileges required" -ForegroundColor $Colors.Error
        return $false
    }
    
    try {
        $needsHiveLoad = -not (Test-UserCurrentlyLoggedIn -TargetUser $TargetUser)
        
        if ($needsHiveLoad) {
            if (-not (Load-UserHive -TargetUser $TargetUser)) {
                throw "Failed to load registry hive"
            }
        }
        
        # Get registry path using Registry:: syntax
        $regPath = Get-RegistryPath -TargetUser $TargetUser
        Write-LogEntry "DEBUG" "Using registry path: $regPath"
        
        if (-not (Test-Path $regPath)) {
            Write-LogEntry "INFO" "Creating Edge policy path"
            New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
        }
        
        # Apply restricted permissions
        $acl = Get-Acl -Path $regPath -ErrorAction Stop
        $userAccount = [System.Security.Principal.NTAccount]$TargetUser
        $acl.PurgeAccessRules($userAccount)
        
        $rule = New-RegistryAccessRule -User $TargetUser -Rights ([System.Security.AccessControl.RegistryRights]::ReadKey)
        $acl.SetAccessRule($rule)
        Set-Acl -Path $regPath -AclObject $acl -ErrorAction Stop
        
        # Validate permissions
        $newAcl = Get-Acl -Path $regPath
        $userHasReadOnly = $newAcl.Access | Where-Object { 
            $_.IdentityReference -like "*$TargetUser" -and 
            $_.RegistryRights -eq "ReadKey" -and 
            $_.AccessControlType -eq "Allow" 
        }
        
        if ($userHasReadOnly) {
            Write-LogEntry "INFO" "Successfully restored and validated ReadKey permissions"
            Write-Host "Successfully restored ReadKey permissions for '$TargetUser'" -ForegroundColor $Colors.Success
            $result = $true
        }
        else {
            Write-LogEntry "ERROR" "Permission validation failed"
            Write-Host "Permission restore validation failed" -ForegroundColor $Colors.Warning
            $result = $false
        }
        
        if ($needsHiveLoad) { Unload-UserHive }
        return $result
    }
    catch {
        Write-LogEntry "ERROR" "Failed to restore permissions: $($_.Exception.Message)"
        Write-Host "Failed to restore permissions: $($_.Exception.Message)" -ForegroundColor $Colors.Error
        if ($needsHiveLoad) { Unload-UserHive }
        return $false
    }
}
#endregion

#region User Interface Functions - WinUtil Style
function Show-Introduction {
    Clear-Host
    Write-Host "`nMicrosoft Edge Registry Permissions Manager" -ForegroundColor $Colors.Title
    Write-Host ("=" * 50) -ForegroundColor $Colors.Title
    Write-Host "`nTarget user: $TargetUser" -ForegroundColor $Colors.Info
    Write-Host "Registry path: HKCU\SOFTWARE\Policies\Microsoft\Edge" -ForegroundColor $Colors.Info
    Write-Host "`nWinUtil-aligned architecture for reliable registry operations" -ForegroundColor $Colors.Info
    Write-Host "Administrator privileges required for permission changes" -ForegroundColor $Colors.Warning
    
    if ($TargetUser -ne $env:USERNAME) {
        Write-Host "Ensure '$TargetUser' has logged in once and is currently logged out" -ForegroundColor $Colors.Warning
    }
    
    Write-Host "`nPress any key to continue..." -ForegroundColor $Colors.Input
    try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") }
    catch { Start-Sleep -Seconds 2 }
}

function Show-MainMenu {
    do {
        Clear-Host
        Write-Host "`nMicrosoft Edge Permissions - Main Menu" -ForegroundColor $Colors.Title
        Write-Host ("=" * 42) -ForegroundColor $Colors.Title
        Write-Host "`nTarget User: $TargetUser" -ForegroundColor $Colors.Info
        Write-Host "Admin Privileges: $(if (Test-AdminPrivileges) { "Yes" } else { "No" })" -ForegroundColor $(if (Test-AdminPrivileges) { $Colors.Success } else { $Colors.Error })
        Write-Host "`n1. Grant FullControl to user '$TargetUser'" -ForegroundColor $Colors.Menu
        Write-Host "2. Restore restricted permissions (ReadKey) for '$TargetUser'" -ForegroundColor $Colors.Menu
        Write-Host "3. Exit without making changes" -ForegroundColor $Colors.Menu
        Write-Host "`nSelect option (1-3): " -ForegroundColor $Colors.Input -NoNewline
        
        $choice = Read-Host
        
        switch ($choice.Trim()) {
            "1" { 
                if (Show-Confirmation "grant FullControl to '$TargetUser'") {
                    return "Grant"
                }
            }
            "2" { 
                if (Show-Confirmation "restore restricted permissions for '$TargetUser'") {
                    return "Restore"
                }
            }
            "3" { 
                if (Show-Confirmation "exit without making changes") {
                    return "Exit"
                }
            }
            default { 
                Write-Host "`nInvalid selection. Please choose 1, 2, or 3." -ForegroundColor $Colors.Error
                Start-Sleep -Seconds 1
            }
        }
    } while ($true)
}

function Show-Confirmation {
    param([string]$ActionDescription)
    
    do {
        Write-Host "`nConfirm: $ActionDescription?" -ForegroundColor $Colors.Warning
        Write-Host "1. Yes" -ForegroundColor $Colors.Menu
        Write-Host "2. No (return to menu)" -ForegroundColor $Colors.Menu
        Write-Host "`nSelect (1-2): " -ForegroundColor $Colors.Input -NoNewline
        
        $choice = Read-Host
        
        switch ($choice.Trim()) {
            "1" { return $true }
            "2" { return $false }
            default { 
                Write-Host "`nInvalid selection." -ForegroundColor $Colors.Error
                Start-Sleep -Seconds 1
            }
        }
    } while ($true)
}

function Show-ExitMessage {
    Clear-Host
    Write-Host "`nNo changes made to registry permissions." -ForegroundColor $Colors.Info
    Write-Host "Press any key to exit..." -ForegroundColor $Colors.Input
    try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") }
    catch { Start-Sleep -Seconds 2 }
}
#endregion

# Main execution - WinUtil style simplified
try {
    Initialize-LogFiles
    Test-UserInput -Username $TargetUser
    $script:UserSid = Get-UserSid -TargetUser $TargetUser
    Write-LogEntry "INFO" "Resolved SID: $script:UserSid"
    
    Show-Introduction
    
    do {
        $userChoice = Show-MainMenu
        Write-LogEntry "INFO" "User selected: $userChoice"
        
        switch ($userChoice) {
            "Grant" {
                if (Grant-FullControl) {
                    Write-Host "`nOperation completed successfully!" -ForegroundColor $Colors.Success
                } else {
                    Write-Host "`nOperation failed. Check logs for details." -ForegroundColor $Colors.Error
                }
                Write-Host "Press any key to exit..." -ForegroundColor $Colors.Input
                try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") }
                catch { Start-Sleep -Seconds 3 }
                break
            }
            "Restore" {
                if (Restore-RestrictedPermissions) {
                    Write-Host "`nOperation completed successfully!" -ForegroundColor $Colors.Success
                } else {
                    Write-Host "`nOperation failed. Check logs for details." -ForegroundColor $Colors.Error
                }
                Write-Host "Press any key to exit..." -ForegroundColor $Colors.Input
                try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") }
                catch { Start-Sleep -Seconds 3 }
                break
            }
            "Exit" {
                Show-ExitMessage
                break
            }
        }
        break
    } while ($true)
}
catch {
    $lineNumber = if ($_.InvocationInfo -and $_.InvocationInfo.ScriptLineNumber) { 
        $_.InvocationInfo.ScriptLineNumber 
    } else { "Unknown" }
    
    $criticalError = "Critical error at line ${lineNumber}: $($_.Exception.Message)"
    
    try { Write-LogEntry "CRITICAL" $criticalError }
    catch { }
    
    Write-Host "`nCritical Error:" -ForegroundColor Red
    Write-Host $criticalError -ForegroundColor Red
    
    if ($script:LogFiles.Activity -and (Test-Path $script:LogFiles.Activity)) {
        Write-Host "`nCheck log: $($script:LogFiles.Activity)" -ForegroundColor White
    }
    
    Write-Host "Press any key to exit..." -ForegroundColor Magenta
    try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") }
    catch { Start-Sleep -Seconds 3 }
}
finally {
    try {
        if ($script:HiveLoaded) {
            Write-LogEntry "INFO" "Cleanup: Unloading hive"
            Unload-UserHive
        }
        
        if ($script:ScriptStartTime) {
            $executionTime = (Get-Date) - $script:ScriptStartTime
            Write-LogEntry "INFO" "Script completed. Runtime: $($executionTime.TotalSeconds)s"
        }
    }
    catch { }
}