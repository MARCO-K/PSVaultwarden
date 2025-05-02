<#
.SYNOPSIS
    Resets or cleans up Vaultwarden environment variables.

.DESCRIPTION
    This internal helper function removes or restores Vaultwarden-related environment variables.
    It's used during cleanup operations or when rolling back changes after errors.

.PARAMETER Restore
    If specified, restores the original environment variables instead of just removing them.

.EXAMPLE
    # Remove all Vaultwarden environment variables
    Reset-Environment
    
.EXAMPLE
    # Restore original environment variable values
    Reset-Environment -Restore

.NOTES
    This is an internal function and should not be called directly by module users.
#>
function Reset-Environment {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [switch]$Restore
    )
    
    try {
        # Check if we should restore original values
        if ($Restore -and $script:OriginalEnvironment) {
            Write-Verbose "Restoring original environment variables"
            
            # Restore each original environment variable
            foreach ($key in $script:OriginalEnvironment.Keys) {
                if ($null -ne $script:OriginalEnvironment[$key]) {
                    # Set environment variable to its original value
                    Set-Item -Path "env:$key" -Value $script:OriginalEnvironment[$key] -Force
                    Write-Verbose "Restored $key environment variable"
                }
                else {
                    # Remove environment variable if it didn't exist originally
                    if (Test-Path -Path "env:$key") {
                        Remove-Item -Path "env:$key" -Force
                        Write-Verbose "Removed $key environment variable"
                    }
                }
            }
        }
        else {
            # Just remove the environment variables
            Write-Verbose "Removing Vaultwarden environment variables"
            
            # Securely remove the client secret first
            if ($env:BW_CLIENTSECRET) {
                # Overwrite with zeros before removing (defensive coding)
                $env:BW_CLIENTSECRET = "0" * $env:BW_CLIENTSECRET.Length
                Remove-Item -Path env:BW_CLIENTSECRET -Force -ErrorAction SilentlyContinue
                Write-Verbose "Removed BW_CLIENTSECRET environment variable"
            }
            
            # Remove other environment variables
            if ($env:BW_CLIENTID) {
                Remove-Item -Path env:BW_CLIENTID -Force -ErrorAction SilentlyContinue
                Write-Verbose "Removed BW_CLIENTID environment variable"
            }
            
            if ($env:BW_URL) {
                Remove-Item -Path env:BW_URL -Force -ErrorAction SilentlyContinue
                Write-Verbose "Removed BW_URL environment variable"
            }
        }
        
        return $true
    }
    catch {
        Write-Error "Error resetting environment variables: $_"
        return $false
    }
}
