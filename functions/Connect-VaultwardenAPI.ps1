function Connect-VaultwardenAPI
{
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
        
    .PARAMETER AutoUnlock
        Attempts to automatically unlock the vault after login. Default is $true.
        
    .PARAMETER UnlockRetries
        Number of times to retry unlocking the vault. Default is 3.
    
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
        [switch]$NoStatus,
        
        [Parameter(Mandatory = $false)]
        [bool]$AutoUnlock = $true,
        
        [Parameter(Mandatory = $false)]
        [int]$UnlockRetries = 3
    )
    
    begin
    {
        # Check if Bitwarden CLI is installed
        try
        {
            $bwVersion = & bw --version
            Write-Verbose "Found Bitwarden CLI version: $bwVersion"
            
            # Log if Write-VWLog is available
            if (Get-Command -Name Write-VWLog -ErrorAction SilentlyContinue)
            {
                Write-VWLog -Message "Found Bitwarden CLI version: $bwVersion" -Level Verbose -Category Authentication
            }
        }
        catch
        {
            $errorMsg = "Bitwarden CLI not found. Please install it and ensure it's available in your PATH."
            
            # Log if Write-VWLog is available
            if (Get-Command -Name Write-VWLog -ErrorAction SilentlyContinue)
            {
                Write-VWLog -Message $errorMsg -Level Error -Category Authentication -EventId 1001 -Exception $_
            }
            
            throw $errorMsg
        }

        # Store the original status of the BW environment variables
        $originalEnvVars = @{
            BW_CLIENTID     = $env:BW_CLIENTID
            BW_CLIENTSECRET = $env:BW_CLIENTSECRET
            BW_URL          = $env:BW_URL
        }

        # Check if already logged in
        if (-not $Force)
        {
            try
            {
                $status = & bw status | ConvertFrom-Json
                if ($status.status -eq "unlocked")
                {
                    if (-not $NoStatus)
                    {
                        Write-Output "Already connected to Vaultwarden with an unlocked vault."
                    }
                    
                    # Log if Write-VWLog is available
                    if (Get-Command -Name Write-VWLog -ErrorAction SilentlyContinue)
                    {
                        Write-VWLog -Message "Already connected to Vaultwarden with an unlocked vault" -Level Information -Category Authentication
                    }
                    
                    return $true
                }
                elseif ($status.status -eq "locked" -and -not $AutoUnlock)
                {
                    if (-not $NoStatus)
                    {
                        Write-Output "Already logged in to Vaultwarden, but vault is locked."
                    }
                    
                    # Log if Write-VWLog is available
                    if (Get-Command -Name Write-VWLog -ErrorAction SilentlyContinue)
                    {
                        Write-VWLog -Message "Already logged in to Vaultwarden, but vault is locked" -Level Information -Category Authentication
                    }
                    
                    return $true
                }
            }
            catch
            {
                Write-Verbose "Not currently logged in or error checking status: $_"
                
                # Log if Write-VWLog is available
                if (Get-Command -Name Write-VWLog -ErrorAction SilentlyContinue)
                {
                    Write-VWLog -Message "Not currently logged in or error checking status" -Level Verbose -Category Authentication
                }
            }
        }
    }
    
    process
    {
        try
        {            
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
            if ($configResult -match "error")
            {
                throw "Failed to configure Vaultwarden server: $configResult"
            }
            
            # Log in using API key authentication
            Write-Verbose "Authenticating to Vaultwarden using API key"
            $loginOutput = & bw login --apikey 2>&1
            
            if ($loginOutput -match "error|failed|not found|invalid")
            {
                throw "Failed to authenticate with Vaultwarden: $loginOutput"
            }
            
            # Check login status
            $status = & bw status | ConvertFrom-Json
            
            # Handle the case where login succeeded but vault is still locked
            if ($status.status -eq "locked" -and $AutoUnlock)
            {
                Write-Verbose "Successfully logged in, but vault is locked. Attempting to unlock..."
                
                # Log if Write-VWLog is available
                if (Get-Command -Name Write-VWLog -ErrorAction SilentlyContinue)
                {
                    Write-VWLog -Message "Successfully logged in, but vault is locked. Attempting to unlock..." -Level Information -Category Authentication
                }
                
                # Try to unlock using the same client secret
                for ($retry = 1; $retry -le $UnlockRetries; $retry++)
                {
                    Write-Verbose "Unlock attempt $retry of $UnlockRetries"
                    
                    # Use the --passwordenv option to avoid exposing the password in process arguments
                    # Store in temp environment variable
                    $env:BW_PASSWORD = $plainTextSecret
                    
                    try
                    {
                        $unlockOutput = & bw unlock --passwordenv BW_PASSWORD 2>&1
                        
                        # Check if unlock succeeded and extract session key
                        if ($unlockOutput -match "BW_SESSION=`"(.+?)`"")
                        {
                            $env:BW_SESSION = $Matches[1]
                            Write-Verbose "Successfully unlocked vault"
                            
                            # Log if Write-VWLog is available
                            if (Get-Command -Name Write-VWLog -ErrorAction SilentlyContinue)
                            {
                                Write-VWLog -Message "Successfully unlocked vault after login" -Level Information -Category Authentication
                            }
                            
                            break
                        }
                    }
                    finally
                    {
                        # Always clear the password environment variable
                        Remove-Item env:BW_PASSWORD -ErrorAction SilentlyContinue
                    }
                    
                    # Wait briefly before retrying
                    if ($retry -lt $UnlockRetries)
                    {
                        Start-Sleep -Milliseconds 500
                    }
                }
                
                # Verify unlock was successful
                $status = & bw status | ConvertFrom-Json
                if ($status.status -ne "unlocked")
                {
                    Write-Warning "Login successful but vault could not be automatically unlocked. Use Unlock-VaultwardenVault to unlock it manually."
                    
                    # Log if Write-VWLog is available
                    if (Get-Command -Name Write-VWLog -ErrorAction SilentlyContinue)
                    {
                        Write-VWLog -Message "Login successful but vault could not be automatically unlocked" -Level Warning -Category Authentication
                    }
                    
                    # Only throw an error if we specifically need an unlocked vault
                    if ($AutoUnlock)
                    {
                        throw "Failed to unlock Vaultwarden vault. Status: $($status.status)"
                    }
                }
            }
            
            # Final status check and output
            if ($status.status -eq "unlocked")
            {
                if (-not $NoStatus)
                {
                    Write-Output "Successfully connected to Vaultwarden with an unlocked vault."
                }
            }
            elseif ($status.status -eq "locked" -and -not $AutoUnlock)
            {
                if (-not $NoStatus)
                {
                    Write-Output "Successfully logged in to Vaultwarden. Vault is locked."
                }
            }
            else
            {
                throw "Unexpected vault status: $($status.status)"
            }
            
            return $true
        }
        catch
        {
            # Restore original environment variables
            $env:BW_CLIENTID = $originalEnvVars.BW_CLIENTID
            $env:BW_CLIENTSECRET = $originalEnvVars.BW_CLIENTSECRET
            $env:BW_URL = $originalEnvVars.BW_URL
            
            # Log if Write-VWLog is available
            if (Get-Command -Name Write-VWLog -ErrorAction SilentlyContinue)
            {
                Write-VWLog -Message "Failed to connect to Vaultwarden: $_" -Level Error -Category Authentication -EventId 1002 -Exception $_
            }
            
            Write-Error "Failed to connect to Vaultwarden: $_"
            return $false
        }
        finally
        {
            # Clean up the plain text secret from memory
            if ($plainTextSecret)
            {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
                Remove-Variable -Name plainTextSecret -ErrorAction SilentlyContinue
            }
        }
    }
}
