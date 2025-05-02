function Connect-VaultwardenAPI {
    <#
    .SYNOPSIS
        Establishes a connection to a Vaultwarden instance using API key authentication.
    
    .DESCRIPTION
        This function handles authentication with a Vaultwarden server using API keys.
        It sets up the necessary environment variables and authenticates the Bitwarden CLI tool.
        No manual interaction is required, making it suitable for use in automated scripts.
    
    .PARAMETER VaultwardenUrl
        The URL of your Vaultwarden instance, e.g., https://vault.example.com
    
    .PARAMETER ClientId
        The API client ID for Vaultwarden authentication.
        
    .PARAMETER ClientSecret
        The API client secret as a SecureString for Vaultwarden authentication.
        
    .PARAMETER Force
        Forces re-authentication even if already logged in.
        
    .PARAMETER NoStatus
        Suppresses status output.
    
    .EXAMPLE
        $secureSecret = ConvertTo-SecureString "your-api-secret" -AsPlainText -Force
        Connect-VaultwardenAPI -VaultwardenUrl "https://vault.example.com" -ClientId "user.12345" -ClientSecret $secureSecret
        
    .NOTES
        This function requires the Bitwarden CLI to be installed and available in the system PATH.
        The authentication session will persist until the PowerShell session ends or until explicitly logged out.
    #>
    
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
        [switch]$Force,
        
        [Parameter(Mandatory = $false)]
        [switch]$NoStatus
    )
    
    begin {
        # Check if Bitwarden CLI is installed
        try {
            $bwVersion = & bw --version
            Write-Verbose "Found Bitwarden CLI version: $bwVersion"
        }
        catch {
            throw "Bitwarden CLI not found. Please install it and ensure it's available in your PATH."
        }

        # Store the original status of the BW environment variables
        $originalEnvVars = @{
            BW_CLIENTID = $env:BW_CLIENTID
            BW_CLIENTSECRET = $env:BW_CLIENTSECRET
            BW_URL = $env:BW_URL
        }

        # Check if already logged in
        if (-not $Force) {
            try {
                $status = & bw status | ConvertFrom-Json
                if ($status.status -eq "unlocked") {
                    if (-not $NoStatus) {
                        Write-Output "Already connected to Vaultwarden."
                    }
                    return $true
                }
            }
            catch {
                Write-Verbose "Not currently logged in or error checking status"
            }
        }
    }
    
    process {
        try {            
            # Convert SecureString to plain text
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret)
            $plainTextSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            
            # Set environment variables for API key authentication
            $env:BW_CLIENTID = $ClientId
            $env:BW_CLIENTSECRET = $plainTextSecret
            $env:BW_URL = $VaultwardenUrl
            
            # Configure CLI to use custom server
            Write-Verbose "Configuring Bitwarden CLI to use server: $VaultwardenUrl"
            $configResult = & bw config server $VaultwardenUrl 2>&1
            if ($configResult -match "error") {
                throw "Failed to configure Vaultwarden server: $configResult"
            }
            
            # Log in using API key authentication
            Write-Verbose "Authenticating to Vaultwarden using API key"
            $loginOutput = & bw login --apikey 2>&1
            
            if ($loginOutput -match "error|failed|not found|invalid") {
                throw "Failed to authenticate with Vaultwarden: $loginOutput"
            }
            
            # Verify login status
            $status = & bw status | ConvertFrom-Json
            if ($status.status -ne "unlocked") {
                throw "Failed to unlock Vaultwarden vault. Status: $($status.status)"
            }
            
            if (-not $NoStatus) {
                Write-Output "Successfully connected to Vaultwarden."
            }
            
            return $true
        }
        catch {
            # Restore original environment variables
            $env:BW_CLIENTID = $originalEnvVars.BW_CLIENTID
            $env:BW_CLIENTSECRET = $originalEnvVars.BW_CLIENTSECRET
            $env:BW_URL = $originalEnvVars.BW_URL
            
            Write-Error "Failed to connect to Vaultwarden: $_"
            return $false
        }
        finally {
            # Clean up the plain text secret from memory
            if ($plainTextSecret) {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
                Remove-Variable -Name plainTextSecret -ErrorAction SilentlyContinue
            }
        }
    }
}
