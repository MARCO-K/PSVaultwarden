<#
.SYNOPSIS
    Provides standardized logging and telemetry for the PSVaultwarden module.

.DESCRIPTION
    This internal helper function implements comprehensive logging capabilities for the PSVaultwarden module.
    It supports multiple output destinations, log levels, and structured telemetry data collection
    while ensuring sensitive information is never logged.

.PARAMETER Message
    The log message to record.

.PARAMETER Level
    The severity level of the log message. Valid values are: Information, Verbose, Warning, Error, and Debug.

.PARAMETER Category
    The functional category of the operation being logged (e.g., Authentication, Vault, Graph, Certificate).

.PARAMETER EventId
    A numeric identifier for the specific type of event being logged.

.PARAMETER Data
    Additional structured data to include with the log entry.

.PARAMETER LogPath
    Optional path to a log file. If not specified, uses the default log path from module configuration.

.PARAMETER NoConsole
    Suppresses console output for this log entry.

.PARAMETER Exception
    An exception object to include with the log entry.

.EXAMPLE
    Write-VWLog -Message "Connected to Vaultwarden" -Level Information -Category Authentication

.EXAMPLE
    Write-VWLog -Message "Failed to retrieve secret" -Level Error -Category Vault -EventId 3001 -Exception $_ -Data @{ SecretName = $name }

.NOTES
    This is an internal function and should not be called directly by module users.
#>
function Write-VWLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Information', 'Verbose', 'Warning', 'Error', 'Debug')]
        [string]$Level = 'Information',
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Authentication', 'Vault', 'Graph', 'Certificate', 'Environment', 'Cache', 'Session', 'General')]
        [string]$Category = 'General',
        
        [Parameter(Mandatory = $false)]
        [int]$EventId = 0,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Data,
        
        [Parameter(Mandatory = $false)]
        [string]$LogPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$NoConsole,
        
        [Parameter(Mandatory = $false)]
        [System.Exception]$Exception
    )
    
    # Initialize module logging if needed
    if (-not $script:LoggingInitialized) {
        # Default log directory in user profile if not specified in module settings
        if (-not $script:LogDirectory) {
            $script:LogDirectory = Join-Path -Path $env:USERPROFILE -ChildPath 'PSVaultwarden\logs'
        }
        
        # Create log directory if it doesn't exist
        if (-not (Test-Path -Path $script:LogDirectory -PathType Container)) {
            try {
                $null = New-Item -Path $script:LogDirectory -ItemType Directory -Force
            }
            catch {
                # If we can't create the log directory, we'll just use console logging
                Write-Warning "Unable to create log directory: $_"
            }
        }
        
        # Default log file name with date
        $script:DefaultLogFile = Join-Path -Path $script:LogDirectory -ChildPath "PSVaultwarden_$((Get-Date).ToString('yyyyMMdd')).log"
        
        # Set logging initialized flag
        $script:LoggingInitialized = $true
    }
    
    # Set log file path
    $logFilePath = if ($LogPath) { $LogPath } else { $script:DefaultLogFile }
    
    # Build log entry (JSON format for structured logging)
    $logEntry = [ordered]@{
        Timestamp   = (Get-Date).ToString('o')  # ISO 8601 format
        Level       = $Level
        Category    = $Category
        EventId     = $EventId
        Message     = $Message
        ModuleName  = 'PSVaultwarden'
        ModuleVersion = $script:ModuleVersion
        Computer    = $env:COMPUTERNAME
        User        = $env:USERNAME
        ProcessId   = $PID
    }
    
    # Add exception details if present
    if ($Exception) {
        $logEntry['ExceptionType'] = $Exception.GetType().FullName
        $logEntry['ExceptionMessage'] = $Exception.Message
        
        # Include stack trace for detailed debugging
        if ($Level -eq 'Error' -or $Level -eq 'Debug') {
            $logEntry['StackTrace'] = $Exception.StackTrace
        }
    }
    
    # Add additional data if provided (sanitize sensitive data)
    if ($Data -and $Data.Count -gt 0) {
        $sanitizedData = @{}
        foreach ($key in $Data.Keys) {
            # Skip sensitive keys entirely
            if ($key -match '(password|secret|key|token|credential|thumb|certificate)' -and $key -notmatch 'name|path|url') {
                $sanitizedData[$key] = '[REDACTED]'
            }
            else {
                $sanitizedData[$key] = $Data[$key]
            }
        }
        $logEntry['Data'] = $sanitizedData
    }
    
    # Convert to JSON
    $jsonEntry = $logEntry | ConvertTo-Json -Compress
    
    # Write to log file
    try {
        Add-Content -Path $logFilePath -Value $jsonEntry -ErrorAction SilentlyContinue
    }
    catch {
        # If file logging fails, make sure console output is enabled
        $NoConsole = $false
        Write-Warning "Failed to write to log file: $_"
    }
    
    # Console output (unless suppressed)
    if (-not $NoConsole) {
        switch ($Level) {
            'Error' {
                Write-Error $Message -ErrorId $EventId -Category FromStdErr
            }
            'Warning' {
                Write-Warning $Message
            }
            'Verbose' {
                Write-Verbose $Message
            }
            'Debug' {
                Write-Debug $Message
            }
            default {
                Write-Information $Message -InformationAction Continue
            }
        }
    }
    
    # Return the log entry for potential telemetry collection
    return $logEntry
}
