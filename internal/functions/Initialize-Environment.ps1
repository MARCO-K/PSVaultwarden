<#
.SYNOPSIS
    Sets up the environment for Vaultwarden CLI interactions.

.DESCRIPTION
    This internal helper function configures the environment variables required for non-interactive
    authentication with the Bitwarden CLI tool when connecting to a Vaultwarden instance.
    It handles secure management of credentials and validates the environment configuration.

.PARAMETER VaultwardenUrl
    The URL of the Vaultwarden instance.

.PARAMETER ClientId
    The API client ID for Vaultwarden.

.PARAMETER ClientSecret
    The API client secret as a SecureString.

.PARAMETER PreserveExisting
    If specified, does not overwrite existing environment variables.

.EXAMPLE
    Initialize-Environment -VaultwardenUrl "https://vault.example.com" -ClientId "user.12345" -ClientSecret $secureSecret

.NOTES
    This is an internal function and should not be called directly by module users.
#>
function Initialize-Environment {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^https?://')]
        [string]$VaultwardenUrl,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ClientId,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.Security.SecureString]$ClientSecret,
        
        [Parameter(Mandatory = $false)]
        [switch]$PreserveExisting
    )
    
    # Store original environment variables to support rollback if needed
    $script:OriginalEnvironment = @{
        BW_CLIENTID     = $env:BW_CLIENTID
        BW_CLIENTSECRET = $env:BW_CLIENTSECRET
        BW_URL          = $env:BW_URL
    }
    
    try {
        # Set URL environment variable if not preserving existing or if it doesn't exist
        if (-not $PreserveExisting -or -not $env:BW_URL) {
            $env:BW_URL = $VaultwardenUrl
            Write-Verbose "Set BW_URL environment variable to: $($VaultwardenUrl)"
        }
        
        # Set client ID environment variable
        if (-not $PreserveExisting -or -not $env:BW_CLIENTID) {
            $env:BW_CLIENTID = $ClientId
            Write-Verbose "Set BW_CLIENTID environment variable"
        }
        
        # Convert SecureString to plain text and set client secret environment variable
        if (-not $PreserveExisting -or -not $env:BW_CLIENTSECRET) {
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret)
            try {
                $env:BW_CLIENTSECRET = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
                Write-Verbose "Set BW_CLIENTSECRET environment variable"
            }
            finally {
                # Always zero out and free the BSTR to minimize exposure
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
            }
        }
        
        # Validate that the environment is properly set up
        if (-not $env:BW_URL -or -not $env:BW_CLIENTID -or -not $env:BW_CLIENTSECRET) {
            throw "Failed to set up Vaultwarden environment variables"
        }
        
        return $true
    }
    catch {
        Write-Error "Error setting up environment variables: $_"
        
        # Rollback on failure
        if (-not $PreserveExisting) {
            Reset-Environment
        }
        
        return $false
    }
}
