<#
.FILENAME
	EdgeSettings_GuestAccount.ps1
.TITLE
	Microsoft Edge Restrictions for Guest Accounts
.SYNOPSIS
    Applies 30 restrictive Edge policies via registry modification for enhanced guest account security
.DESCRIPTION
    Hardens Microsoft Edge browser configuration for guest and temporary user accounts through systematic registry policy deployment. Implements 30 security-focused restrictions across autofill, downloads, notifications, tracking, and performance features. Features automatic backup and restore capabilities, comprehensive logging with separate activity and rollback logs, graceful error handling with line-number reporting, and user confirmation prompts to prevent accidental modifications.
.AUTHOR
    Joshua Bishop - developer01@joshspace.com
.VERSION
    1.0.1
.DATE
    2025-09-14
.NOTES
    Tested in Windows 11 24H2 Build 26100.6584 and MS Edge 140.0.3485.66 (x64)
    Can be run as a standard user since it uses HKCU for user-specific settings.
#>

# Initialize global variables
$script:LogFiles = @{}
$script:OriginalSettings = @{}
$script:AppliedSettings = @()
$script:ScriptStartTime = Get-Date
$script:ErrorOccurred = $false

# Color scheme for user-friendly output
$Colors = @{
    Title = "Cyan"
    Info = "White" 
    Success = "Green"
    Warning = "Yellow"
    Error = "Red"
    Menu = "Yellow"
    Input = "Magenta"
}

# Edge settings configuration organized by category
$script:EdgeSettings = @{
    # Security Settings
    'F12DeveloperTools' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'AllowDeveloperTools'
        Value = 0
        Description = 'Disable F12 developer tools'
    }
    'PUABlocking' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'SmartScreenPuaEnabled'
        Value = 1
        Description = 'Enable PUA blocking'
    }
    'SuspiciousDownloads' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'SmartScreenEnabled'
        Value = 1
        Description = 'Enable blocking suspicious downloads'
    }
    'InsecureDownloads' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'InsecureContentBlockedForUrls'
        Value = '*'
        Description = 'Block all insecure downloads'
    }
    'DangerousFiles' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'DownloadRestrictions'
        Value = 1
        Description = 'Block dangerous file types'
    }
    'AutomaticDownloads' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'AutomaticDownloadsAllowed'
        Value = 0
        Description = 'Disable automatic downloads'
    }
    'DownloadPrompts' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'PromptForDownloadLocation'
        Value = 1
        Description = 'Ask where to save each file'
    }
    
    # Privacy Settings
    'PasswordSaving' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'PasswordManagerEnabled'
        Value = 0
        Description = 'Disable password saving'
    }
    'PasswordGeneration' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'PasswordGeneratorEnabled'
        Value = 0
        Description = 'Disable password generation'
    }
    'AddressAutofill' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'AddressBarMicrosoftSearchInBingProviderEnabled'
        Value = 0
        Description = 'Disable address autofill'
    }
    'PaymentAutofill' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'PaymentMethodQueryEnabled'
        Value = 0
        Description = 'Disable payment method autofill'
    }
    'FormAutofill' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'AutofillAddressEnabled'
        Value = 0
        Description = 'Disable form autofill'
    }
    'WebsiteNotifications' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'DefaultNotificationsSetting'
        Value = 2
        Description = 'Block all website notifications'
    }
    'PrivateBrowsing' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'IncognitoModeAvailability'
        Value = 1
        Description = 'Disable private browsing'
    }
    'HistoryScreenshots' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'ShowHistoryThumbnails'
        Value = 0
        Description = 'Disable saving screenshots of sites for history'
    }
    'AutofillDataCollection' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'EdgeAutofillMLEnabled'
        Value = 0
        Description = 'Disable collecting field labels to improve autofill'
    }
    'ExpressCheckout' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'EdgeShoppingAssistantEnabled'
        Value = 0
        Description = 'Disable express checkout on shopping sites'
    }
    
    # Performance Settings
    'StartupBoost' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'StartupBoostEnabled'
        Value = 0
        Description = 'Disable startup boost'
    }
    'BackgroundApps' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'BackgroundModeEnabled'
        Value = 0
        Description = 'Block background apps'
    }
    'PreloadPages' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'NetworkPredictionOptions'
        Value = 2
        Description = 'Disable preloading pages for faster browsing'
    }
    
    # User Interface Settings
    'FavoritesBar' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'BookmarkBarEnabled'
        Value = 1
        Description = 'Show favorites bar'
    }
    'NewTabLayout' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'NewTabPageContentEnabled'
        Value = 0
        Description = 'Set focused (minimal) new tab layout'
    }
    'NewTabContent' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'NewTabPageQuickLinksEnabled'
        Value = 1
        Description = 'Show top sites only on new tab'
    }
    'StartupBehavior' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'RestoreOnStartup'
        Value = 5
        Description = 'Open new tab page on startup'
    }
    'HomePage' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'HomepageIsNewTabPage'
        Value = 1
        Description = 'Use new tab page as home page'
    }
    'SponsoredLinks' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'PromotedLinksEnabled'
        Value = 0
        Description = 'Disable promoted or sponsored quick links'
    }
    'QuickLinksNewTab' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'NewTabPageQuickLinksOpenInNewTab'
        Value = 0
        Description = 'Open quick links in the same tab on the new tab page'
    }
    
    # System Settings
    'SearchEngine' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'DefaultSearchProviderEnabled'
        Value = 1
        Description = 'Enable default search provider'
    }
    'SearchEngineName' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'DefaultSearchProviderName'
        Value = 'Google'
        Description = 'Set default search provider name to Google'
    }
    'SearchEngineURL' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'DefaultSearchProviderSearchURL'
        Value = 'https://www.google.com/search?q={searchTerms}'
        Description = 'Set default search provider URL to Google'
    }
    'PDFViewer' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'AlwaysOpenPdfExternally'
        Value = 0
        Description = 'Always open PDFs in Edge'
    }
    'DownloadLocation' = @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'DownloadDirectory'
        Value = 'NOT_SET'
        Description = 'Use default Downloads folder'
    }
}

function Initialize-LogFiles {
    $timestamp = Get-Date -Format "yyyyMMddHHmmss"
    $scriptDir = Split-Path -Parent $MyInvocation.ScriptName
    
    $script:LogFiles = @{
        Settings = Join-Path $scriptDir ("edgesett_" + $timestamp + ".txt")
        Activity = Join-Path $scriptDir ("ERSLog_" + $timestamp + ".txt")
        Rollback = Join-Path $scriptDir ("RollbackLog_" + $timestamp + ".txt")
    }
    
    Write-LogEntry "INFO" "Log files initialized"
    Write-LogEntry "INFO" ("Settings log: " + $script:LogFiles.Settings)
    Write-LogEntry "INFO" ("Activity log: " + $script:LogFiles.Activity)
    Write-LogEntry "INFO" ("Script started by user: " + $env:USERNAME)
    Write-LogEntry "INFO" ("Script path: " + $MyInvocation.ScriptName)
}

function Write-LogEntry {
    param(
        [string]$Level,
        [string]$Message,
        [string]$LogType = "Activity"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logEntry = "[" + $timestamp + "] [" + $Level + "] " + $Message
    
    try {
        switch ($LogType) {
            "Activity" { 
                Add-Content -Path $script:LogFiles.Activity -Value $logEntry -ErrorAction SilentlyContinue
            }
            "Settings" { 
                Add-Content -Path $script:LogFiles.Settings -Value $logEntry -ErrorAction SilentlyContinue
            }
            "Rollback" { 
                Add-Content -Path $script:LogFiles.Rollback -Value $logEntry -ErrorAction SilentlyContinue
            }
        }
    }
    catch {
        # Silently continue if logging fails
    }
}

function Show-Introduction {
    Clear-Host
    Write-LogEntry "INFO" "Displaying introduction screen"
    
    Write-Host ("`nMS Edge Restrictions for Guest Accounts") -ForegroundColor $Colors.Title
    Write-Host ("=" * 45) -ForegroundColor $Colors.Title
    Write-Host ("`nThis script will configure many of the settings for Microsoft Edge.") -ForegroundColor $Colors.Info
    Write-Host ("These settings will be configured for use on a Guest or Temporary") -ForegroundColor $Colors.Info
    Write-Host ("User account needing highly restrictive settings.") -ForegroundColor $Colors.Info
    Write-Host ("`nPress any key to continue...") -ForegroundColor $Colors.Input
    
    Write-LogEntry "DEBUG" "Waiting for user input at introduction screen"
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Write-LogEntry "DEBUG" "User pressed key at introduction screen"
}

function Show-MainMenu {
    do {
        Clear-Host
        Write-LogEntry "INFO" "Displaying main menu"
        
        Write-Host ("`nMS Edge Restrictions - Main Menu") -ForegroundColor $Colors.Title
        Write-Host ("=" * 35) -ForegroundColor $Colors.Title
        Write-Host ("`n1. Continue (Apply restrictive settings)") -ForegroundColor $Colors.Menu
        Write-Host ("2. Undo (Restore previous settings)") -ForegroundColor $Colors.Menu  
        Write-Host ("3. Exit (Make no changes)") -ForegroundColor $Colors.Menu
        Write-Host ("`nPlease select an option (1-3):") -ForegroundColor $Colors.Input
        
        Write-LogEntry "DEBUG" "Waiting for menu selection"
        $choice = Read-Host
        Write-LogEntry "DEBUG" ("User selected menu option: " + $choice)
        
        switch ($choice) {
            "1" { 
                if (Show-Confirmation "apply these restrictive Edge settings" "Apply restrictive settings" "Return to menu") {
                    Write-LogEntry "INFO" "User confirmed Continue option"
                    return "Continue"
                }
            }
            "2" { 
                if (Show-Confirmation "restore previous Edge settings" "Restore previous settings" "Return to menu") {
                    Write-LogEntry "INFO" "User confirmed Undo option"
                    return "Undo"
                }
            }
            "3" { 
                if (Show-Confirmation "exit without making changes" "Exit (Make no changes)" "Return to menu") {
                    Write-LogEntry "INFO" "User confirmed Exit option"
                    return "Exit"
                }
            }
            default { 
                Write-Host ("`nInvalid selection. Please choose 1, 2, or 3.") -ForegroundColor $Colors.Error
                Write-LogEntry "WARN" ("Invalid menu selection: " + $choice)
                Start-Sleep -Seconds 2
            }
        }
    } while ($true)
}

function Show-Confirmation {
    param(
        [string]$ActionDescription,
        [string]$Option1Text,
        [string]$Option2Text
    )
    
    do {
        $confirmMessage = "`nAre you sure you want to " + $ActionDescription + "?"
        Write-Host $confirmMessage -ForegroundColor $Colors.Warning
        Write-Host ("1. " + $Option1Text) -ForegroundColor $Colors.Menu
        Write-Host ("2. " + $Option2Text) -ForegroundColor $Colors.Menu
        Write-Host ("`nPlease select an option (1-2):") -ForegroundColor $Colors.Input
        
        Write-LogEntry "DEBUG" ("Showing confirmation for action: " + $ActionDescription)
        $confirm = Read-Host
        Write-LogEntry "DEBUG" ("User confirmation response: " + $confirm)
        
        switch ($confirm) {
            "1" { 
                Write-LogEntry "DEBUG" ("User confirmed action: " + $ActionDescription)
                return $true 
            }
            "2" { 
                Write-LogEntry "DEBUG" ("User chose Back for action: " + $ActionDescription)
                return $false 
            }
            default { 
                Write-Host ("`nInvalid selection. Please choose 1 or 2.") -ForegroundColor $Colors.Error
                Write-LogEntry "WARN" ("Invalid confirmation response: " + $confirm)
                Start-Sleep -Seconds 1
            }
        }
    } while ($true)
}

function Test-RegistryPath {
    param([string]$Path)
    
    Write-LogEntry "DEBUG" ("Testing registry path: " + $Path)
    $exists = Test-Path $Path
    Write-LogEntry "DEBUG" ("Registry path exists: " + $exists)
    return $exists
}

function Get-RegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )
    
    Write-LogEntry "DEBUG" ("Getting registry value: " + $Path + "\" + $Name)
    
    try {
        if (Test-RegistryPath $Path) {
            $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($value) {
                Write-LogEntry "DEBUG" ("Registry value found: " + $value.$Name)
                return $value.$Name
            }
        }
        Write-LogEntry "DEBUG" "Registry value not found, returning NOT_SET"
        return "NOT_SET"
    }
    catch {
        Write-LogEntry "ERROR" ("Error getting registry value " + $Path + "\" + $Name + " : " + $_.Exception.Message)
        return "NOT_SET"
    }
}

function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWORD"
    )
    
    Write-LogEntry "DEBUG" ("Setting registry value: " + $Path + "\" + $Name + " = " + $Value + " (Type: " + $Type + ")")
    
    try {
        if (!(Test-RegistryPath $Path)) {
            Write-LogEntry "DEBUG" ("Creating registry path: " + $Path)
            New-Item -Path $Path -Force | Out-Null
            Write-Host ("Created registry path: " + $Path) -ForegroundColor $Colors.Success
        }
        
        if ($Value -eq "NOT_SET") {
            Write-LogEntry "DEBUG" ("Skipping NOT_SET value for " + $Path + "\" + $Name)
            return $true
        }
        
        # Determine the correct registry type based on the value
        $registryType = $Type
        if ($Value -is [string] -and $Value -ne "NOT_SET") {
            $registryType = "String"
        }
        
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $registryType
        Write-LogEntry "INFO" ("Successfully set " + $Path + "\" + $Name + " = " + $Value)
        Write-Host ("Set " + $Name + " = " + $Value + " in " + $Path) -ForegroundColor $Colors.Info
        return $true
    }
    catch {
        Write-LogEntry "ERROR" ("Failed to set registry value " + $Path + "\" + $Name + " : " + $_.Exception.Message + " (Line: " + $_.InvocationInfo.ScriptLineNumber + ")")
        throw
    }
}

function Remove-RegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )
    
    Write-LogEntry "DEBUG" ("Removing registry value: " + $Path + "\" + $Name)
    
    try {
        if (Test-RegistryPath $Path) {
            Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            Write-LogEntry "INFO" ("Successfully removed " + $Path + "\" + $Name)
        }
        return $true
    }
    catch {
        Write-LogEntry "ERROR" ("Failed to remove registry value " + $Path + "\" + $Name + " : " + $_.Exception.Message)
        return $false
    }
}

function Backup-CurrentSettings {
    Write-Host ("`nBacking up current Edge settings...") -ForegroundColor $Colors.Info
    Write-LogEntry "INFO" "Starting backup of current settings"
    
    $backupHeader = "# Edge Settings Backup - " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + "`n# Original settings before applying restrictions`n"
    Add-Content -Path $script:LogFiles.Settings -Value $backupHeader
    
    foreach ($settingName in $script:EdgeSettings.Keys) {
        $setting = $script:EdgeSettings[$settingName]
        Write-LogEntry "DEBUG" ("Backing up setting: " + $settingName)
        
        try {
            $currentValue = Get-RegistryValue -Path $setting.Path -Name $setting.Name
            $script:OriginalSettings[$settingName] = $currentValue
            
            $logEntry = $settingName + "|" + $setting.Path + "|" + $setting.Name + "|" + $currentValue
            Add-Content -Path $script:LogFiles.Settings -Value $logEntry
            
            Write-LogEntry "INFO" ("Backed up " + $settingName + " : " + $currentValue)
            Write-Host ("  [OK] " + $setting.Description) -ForegroundColor $Colors.Success
        }
        catch {
            Write-LogEntry "ERROR" ("Failed to backup setting " + $settingName + " : " + $_.Exception.Message + " (Line: " + $_.InvocationInfo.ScriptLineNumber + ")")
            throw ("Error backing up " + $settingName + " at line " + $_.InvocationInfo.ScriptLineNumber + ": " + $_.Exception.Message)
        }
    }
    
    Write-LogEntry "INFO" "Settings backup completed successfully"
    Write-Host ("`nSettings backup completed.") -ForegroundColor $Colors.Success
}

function Apply-RestrictiveSettings {
    Write-Host ("`nApplying restrictive Edge settings...") -ForegroundColor $Colors.Info
    Write-LogEntry "INFO" "Starting application of restrictive settings"
    
    $settingCount = 0
    foreach ($settingName in $script:EdgeSettings.Keys) {
        $setting = $script:EdgeSettings[$settingName]
        Write-LogEntry "DEBUG" ("Applying setting: " + $settingName)
        
        try {
            if ($setting.Value -ne "NOT_SET") {
                Set-RegistryValue -Path $setting.Path -Name $setting.Name -Value $setting.Value
                $script:AppliedSettings += $settingName
            }
            
            Write-LogEntry "INFO" ("Applied " + $settingName + " : " + $setting.Value)
            Write-Host ("  [OK] " + $setting.Description) -ForegroundColor $Colors.Success
            $settingCount++
        }
        catch {
            $script:ErrorOccurred = $true
            $errorMsg = "Error applying " + $settingName + " at line " + $_.InvocationInfo.ScriptLineNumber + ": " + $_.Exception.Message
            Write-LogEntry "ERROR" $errorMsg
            throw $errorMsg
        }
    }
    
    Write-LogEntry "INFO" ("Applied " + $settingCount + " restrictive settings successfully")
    Write-Host ("`nAll " + $settingCount + " restrictive settings applied successfully!") -ForegroundColor $Colors.Success
}

function Start-Rollback {
    param([string]$ErrorMessage)
    
    Write-Host ("`nError occurred: " + $ErrorMessage) -ForegroundColor $Colors.Error
    Write-Host ("Rolling back changes...") -ForegroundColor $Colors.Warning
    
    Write-LogEntry "ERROR" ("Starting rollback due to error: " + $ErrorMessage)
    Write-LogEntry "INFO" "Beginning automatic rollback of partial changes" "Rollback"
    
    $rollbackCount = 0
    foreach ($settingName in $script:AppliedSettings) {
        try {
            $setting = $script:EdgeSettings[$settingName]
            $originalValue = $script:OriginalSettings[$settingName]
            
            Write-LogEntry "DEBUG" ("Rolling back setting: " + $settingName + " to " + $originalValue) "Rollback"
            
            if ($originalValue -eq "NOT_SET") {
                Remove-RegistryValue -Path $setting.Path -Name $setting.Name
                Write-LogEntry "INFO" ("Removed " + $settingName + " (was NOT_SET)") "Rollback"
            }
            else {
                Set-RegistryValue -Path $setting.Path -Name $setting.Name -Value $originalValue
                Write-LogEntry "INFO" ("Restored " + $settingName + " to " + $originalValue) "Rollback"
            }
            
            Write-Host ("  [RESTORED] " + $setting.Description) -ForegroundColor $Colors.Info
            $rollbackCount++
        }
        catch {
            Write-LogEntry "ERROR" ("Failed to rollback " + $settingName + " : " + $_.Exception.Message) "Rollback"
            Write-Host ("  [ERROR] Failed to restore " + $setting.Description) -ForegroundColor $Colors.Error
        }
    }
    
    Write-LogEntry "INFO" ("Rollback completed. Restored " + $rollbackCount + " settings") "Rollback"
    Write-Host ("`nRollback completed. Restored " + $rollbackCount + " settings.") -ForegroundColor $Colors.Info
}

function Restore-PreviousSettings {
    Write-Host ("`nLooking for previous settings backup...") -ForegroundColor $Colors.Info
    Write-LogEntry "INFO" "Starting restore of previous settings"
    
    # Find the most recent settings backup file
    $scriptDir = Split-Path -Parent $MyInvocation.ScriptName
    $backupFiles = Get-ChildItem -Path $scriptDir -Filter "edgesett_*.txt" | Sort-Object LastWriteTime -Descending
    
    if ($backupFiles.Count -eq 0) {
        Write-Host ("`nNo previous settings backup found.") -ForegroundColor $Colors.Warning
        Write-Host ("You must run 'Apply restrictive settings' first to create a backup.") -ForegroundColor $Colors.Info
        Write-LogEntry "WARN" "No backup files found for restore operation"
        Write-Host ("`nPress any key to return to menu...") -ForegroundColor $Colors.Input
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        return
    }
    
    $latestBackup = $backupFiles[0]
    Write-Host ("Found backup file: " + $latestBackup.Name) -ForegroundColor $Colors.Info
    Write-LogEntry "INFO" ("Using backup file: " + $latestBackup.FullName)
    
    try {
        $backupContent = Get-Content -Path $latestBackup.FullName | Where-Object { $_ -notmatch "^#" -and $_.Trim() -ne "" }
        
        Write-Host ("Restoring previous settings...") -ForegroundColor $Colors.Info
        $restoreCount = 0
        
        foreach ($line in $backupContent) {
            $parts = $line.Split("|")
            if ($parts.Count -eq 4) {
                $settingName = $parts[0]
                $path = $parts[1] 
                $name = $parts[2]
                $value = $parts[3]
                
                Write-LogEntry "DEBUG" ("Restoring setting: " + $settingName + " = " + $value)
                
                try {
                    if ($value -eq "NOT_SET") {
                        Remove-RegistryValue -Path $path -Name $name
                        Write-LogEntry "INFO" ("Removed " + $settingName + " (restored to NOT_SET)")
                    }
                    else {
                        Set-RegistryValue -Path $path -Name $name -Value $value
                        Write-LogEntry "INFO" ("Restored " + $settingName + " to " + $value)
                    }
                    
                    if ($script:EdgeSettings.ContainsKey($settingName)) {
                        Write-Host ("  [OK] " + $script:EdgeSettings[$settingName].Description) -ForegroundColor $Colors.Success
                    }
                    else {
                        Write-Host ("  [OK] " + $settingName) -ForegroundColor $Colors.Success
                    }
                    
                    $restoreCount++
                }
                catch {
                    Write-LogEntry "ERROR" ("Failed to restore " + $settingName + " : " + $_.Exception.Message)
                    Write-Host ("  [ERROR] Failed to restore " + $settingName) -ForegroundColor $Colors.Error
                }
            }
        }
        
        Write-LogEntry "INFO" ("Restore completed. " + $restoreCount + " settings restored")
        Write-Host ("`nRestore completed! " + $restoreCount + " settings restored.") -ForegroundColor $Colors.Success
    }
    catch {
        Write-LogEntry "ERROR" ("Failed to read backup file: " + $_.Exception.Message)
        Write-Host ("Error reading backup file: " + $_.Exception.Message) -ForegroundColor $Colors.Error
    }
    
    Write-Host ("`nPress any key to continue...") -ForegroundColor $Colors.Input
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Show-ExitMessage {
    Clear-Host
    Write-LogEntry "INFO" "Displaying exit message - no changes made"
    Write-Host ("`nNo changes to your computer were made.") -ForegroundColor $Colors.Info
    Write-Host ("Press any key to close this window...") -ForegroundColor $Colors.Input
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Main script execution
try {
    Initialize-LogFiles
    Show-Introduction
    
    do {
        $userChoice = Show-MainMenu
        Write-LogEntry "INFO" ("Processing user choice: " + $userChoice)
        
        switch ($userChoice) {
            "Continue" {
                try {
                    Backup-CurrentSettings
                    Apply-RestrictiveSettings
                    Write-Host ("`nEdge restrictions have been successfully applied!") -ForegroundColor $Colors.Success
                    Write-Host ("Press any key to exit...") -ForegroundColor $Colors.Input
                    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                    break
                }
                catch {
                    Start-Rollback -ErrorMessage $_.Exception.Message
                    Write-Host ("`nPress any key to continue...") -ForegroundColor $Colors.Input
                    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                    continue
                }
            }
            "Undo" {
                Restore-PreviousSettings
                continue
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
    $criticalError = "Critical script error at line " + $_.InvocationInfo.ScriptLineNumber + ": " + $_.Exception.Message
    Write-LogEntry "CRITICAL" $criticalError
    
    Write-Host ("`nCritical Error Occurred:") -ForegroundColor $Colors.Error
    Write-Host $criticalError -ForegroundColor $Colors.Error
    
    if ($script:AppliedSettings.Count -gt 0) {
        Write-Host ("`nAttempting emergency rollback...") -ForegroundColor $Colors.Warning
        Start-Rollback -ErrorMessage $criticalError
    }
    
    Write-Host ("`nScript terminated due to critical error.") -ForegroundColor $Colors.Error
    Write-Host ("Check the log files for detailed error information.") -ForegroundColor $Colors.Info
    Write-Host ("Press any key to exit...") -ForegroundColor $Colors.Input
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
finally {
    $scriptEndTime = Get-Date
    $executionTime = $scriptEndTime - $script:ScriptStartTime
    Write-LogEntry "INFO" ("Script execution completed. Total time: " + $executionTime.TotalSeconds + " seconds")
}