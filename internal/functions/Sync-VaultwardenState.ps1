<#
.SYNOPSIS
    Synchronizes the Vaultwarden vault with the server.

.DESCRIPTION
    This internal helper function ensures that the local Vaultwarden vault is synchronized with the server.
    It handles the synchronization process, error retries, and verification of sync status.

.PARAMETER Force
    Forces a synchronization even if the vault was recently synchronized.

.PARAMETER MaxRetries
    Maximum number of synchronization retries in case of failure. Default is 3.

.PARAMETER RetryDelaySeconds
    Delay in seconds between retry attempts. Default is 2 seconds.

.EXAMPLE
    Sync-VaultwardenState

.EXAMPLE
    Sync-VaultwardenState -Force -MaxRetries 5 -RetryDelaySeconds 3

.NOTES
    This is an internal function and should not be called directly by module users.
#>
function Sync-VaultwardenState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3,
        
        [Parameter(Mandatory = $false)]
        [int]$RetryDelaySeconds = 2
    )
    
    # Track last sync time to avoid unnecessary syncs
    if (-not $script:LastSyncTime) {
        $script:LastSyncTime = [datetime]::MinValue
    }
    
    # Check if we need to sync (if not forced and last sync was less than 5 minutes ago)
    if (-not $Force -and ([datetime]::Now - $script:LastSyncTime).TotalMinutes -lt 5) {
        Write-Verbose "Skipping sync - last sync was less than 5 minutes ago"
        return $true
    }
    
    # Check if we're authenticated
    try {
        $status = & bw status | ConvertFrom-Json
        if ($status.status -ne "unlocked") {
            throw "Not authenticated with Vaultwarden. Please run Connect-VaultwardenAPI first."
        }
    }
    catch {
        Write-Error "Failed to check Vaultwarden status: $_"
        return $false
    }
    
    # Perform sync with retries
    $syncSuccess = $false
    $retryCount = 0
    $lastError = $null
    
    while (-not $syncSuccess -and $retryCount -le $MaxRetries) {
        try {
            if ($retryCount -gt 0) {
                Write-Verbose "Retry attempt $retryCount of $MaxRetries after $RetryDelaySeconds seconds"
                Start-Sleep -Seconds $RetryDelaySeconds
            }
            
            # Execute sync command
            Write-Verbose "Syncing Vaultwarden vault with server"
            $syncOutput = & bw sync 2>&1
            
            # Check for errors in output
            if ($syncOutput -match "error|failed|not found|invalid") {
                throw "Sync error: $syncOutput"
            }
            
            $syncSuccess = $true
            $script:LastSyncTime = [datetime]::Now
            Write-Verbose "Vaultwarden vault synchronized successfully"
        }
        catch {
            $retryCount++
            $lastError = $_
            Write-Verbose "Sync attempt failed: $_"
            
            # Break if we've reached max retries
            if ($retryCount -gt $MaxRetries) {
                Write-Error "Failed to sync Vaultwarden vault after $MaxRetries attempts: $lastError"
                return $false
            }
        }
    }
    
    # Verify that vault is still accessible after sync
    try {
        $verifyStatus = & bw status | ConvertFrom-Json
        if ($verifyStatus.status -ne "unlocked") {
            throw "Vault is no longer unlocked after synchronization"
        }
    }
    catch {
        Write-Error "Failed to verify vault status after sync: $_"
        return $false
    }
    
    return $syncSuccess
}
