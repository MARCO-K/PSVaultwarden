function Unlock-VaultwardenVault
{
    <#
    .SYNOPSIS
        Unlocks a Vaultwarden vault using password or session key.
    
    .DESCRIPTION
        This function unlocks a Vaultwarden vault using either a password or a session key.
        It supports session management to handle token expiration, vault data caching to 
        improve performance, and uses certificate-based authentication when available.
    
    .PARAMETER MasterPassword
        The master password for the vault as a SecureString.
        
    .PARAMETER SessionKey
        An existing session key to unlock the vault.
        
    .PARAMETER VaultPath
        Optional path to the vault data file if not using the default location.
        
    .PARAMETER SessionTimeout
        The timeout period in minutes before the session requires re-authentication.
        Default is 60 minutes.
        
    .PARAMETER UseCertificate
        Use certificate-based authentication if available instead of password.
        
    .PARAMETER CertificateThumbprint
        The thumbprint of the certificate to use for authentication.
        
    .PARAMETER EnableCache
        Enable caching of vault data to improve performance. Default is $true.
        
    .PARAMETER CacheTimeout
        The timeout period in minutes before the cache is refreshed. Default is 10 minutes.
        
    .PARAMETER NoStatus
        Suppresses status output.
        
    .PARAMETER Force
        Forces re-authentication even if the vault is already unlocked.
    
    .EXAMPLE
        $password = Read-Host -AsSecureString -Prompt "Enter your master password"
        Unlock-VaultwardenVault -MasterPassword $password
        
    .EXAMPLE
        Unlock-VaultwardenVault -SessionKey $env:BW_SESSION
        
    .EXAMPLE
        Unlock-VaultwardenVault -UseCertificate -CertificateThumbprint "1a2b3c4d5e6f7g8h9i0j"
        
    .NOTES
        This function manages session persistence and implements proper token expiration handling.
        It also provides performance optimizations through intelligent caching of vault data.
    #>
    
    [CmdletBinding(DefaultParameterSetName = 'Password')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Password')]
        [ValidateNotNull()]
        [System.Security.SecureString]$MasterPassword,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'Session')]
        [ValidateNotNullOrEmpty()]
        [string]$SessionKey,
        
        [Parameter(Mandatory = $false)]
        [string]$VaultPath,
        
        [Parameter(Mandatory = $false)]
        [int]$SessionTimeout = 60,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [switch]$UseCertificate,
        
        [Parameter(Mandatory = $false, ParameterSetName = 'Certificate')]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateThumbprint,
        
        [Parameter(Mandatory = $false)]
        [bool]$EnableCache = $true,
        
        [Parameter(Mandatory = $false)]
        [int]$CacheTimeout = 10,
        
        [Parameter(Mandatory = $false)]
        [switch]$NoStatus,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    begin
    {
        # Check if Bitwarden CLI is installed
        try
        {
            $bwVersion = & bw --version
            Write-VWLog -Message "Found Bitwarden CLI version: $bwVersion" -Level Verbose -Category Authentication
        }
        catch
        {
            $errorMsg = "Bitwarden CLI not found. Please install it and ensure it's available in your PATH."
            Write-VWLog -Message $errorMsg -Level Error -Category Authentication -EventId 1001 -Exception $_
            throw $errorMsg
        }

        # Verify we have a connection to Vaultwarden
        try
        {
            $status = & bw status | ConvertFrom-Json
            Write-VWLog -Message "Current Vaultwarden status: $($status.status)" -Level Verbose -Category Authentication
        }
        catch
        {
            $errorMsg = "Failed to check Vaultwarden status. Make sure you're connected using Connect-VaultwardenAPI."
            Write-VWLog -Message $errorMsg -Level Error -Category Authentication -EventId 1002 -Exception $_
            throw $errorMsg
        }
        
        # Check if vault is already unlocked and we're not forcing re-auth
        if (-not $Force -and $status.status -eq "unlocked")
        {
            Write-VWLog -Message "Vault is already unlocked" -Level Information -Category Authentication
            if (-not $NoStatus)
            {
                Write-Output "Vault is already unlocked."
            }
            
            # Update in-memory session timestamp for tracking
            if (-not $script:SessionInfo)
            {
                $script:SessionInfo = @{
                    LastUnlocked     = Get-Date
                    ExpiresAt        = (Get-Date).AddMinutes($SessionTimeout)
                    IsCacheValid     = $true
                    LastCacheRefresh = Get-Date
                }
            }
            
            return $true
        }
        
        # Check if the session has expired
        if ($script:SessionInfo -and (Get-Date) -gt $script:SessionInfo.ExpiresAt)
        {
            Write-VWLog -Message "Session has expired and requires re-authentication" -Level Warning -Category Session
            $Force = $true
        }
    }
    
    process
    {
        try
        {
            # Variable to hold the unlock command output
            $unlockOutput = $null
            $sessionToken = $null
            
            # Different unlock approaches based on parameter set
            switch ($PSCmdlet.ParameterSetName)
            {
                'Password'
                {
                    Write-VWLog -Message "Attempting to unlock vault with master password" -Level Verbose -Category Authentication
                    
                    # Convert SecureString to plain text
                    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($MasterPassword)
                    $plainTextPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
                    
                    try
                    {
                        # Set environment variable for the password
                        $env:BW_PASSWORD = $plainTextPassword
                        
                        # Using --passwordenv argument
                        Write-VWLog -Message "Attempting unlock via --passwordenv BW_PASSWORD" -Level Debug -Category Authentication
                        $unlockOutput = & bw unlock --passwordenv BW_PASSWORD --raw 2>&1
                        Write-VWLog -Message "Raw output from 'bw unlock --passwordenv BW_PASSWORD --raw': $unlockOutput" -Level Debug -Category Authentication

                        # Check if output is a valid session token (using --raw should just output the token)
                        if ($unlockOutput -ne $null -and $unlockOutput -notmatch "error|failed|not found|invalid|unauthorized" -and $unlockOutput.Length -gt 20) # Basic check for a token-like string
                        {
                            $sessionToken = $unlockOutput.Trim()
                            Write-VWLog -Message "Successfully obtained session token via --passwordenv" -Level Verbose -Category Authentication
                        }
                        else
                        {
                            Write-VWLog -Message "Failed to obtain session token via --passwordenv. Output: $unlockOutput" -Level Warning -Category Authentication
                            # Optional: Fallback to original pipe method or throw error immediately
                            # Write-VWLog -Message "Falling back to pipe method..." -Level Debug -Category Authentication
                            # $unlockOutput = $plainTextPassword | & bw unlock 2>&1
                            # Write-VWLog -Message "Raw output from pipe method: $unlockOutput" -Level Debug -Category Authentication
                            # if ($unlockOutput -match "BW_SESSION=`"(.+?)`"")
                            # {
                            #    $sessionToken = $Matches[1]
                            #    Write-VWLog -Message "Successfully obtained session token via pipe method" -Level Verbose -Category Authentication
                            # }
                        }
                    }
                    finally
                    {
                        # Securely clear the password variable and environment variable
                        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
                        Remove-Variable -Name plainTextPassword -ErrorAction SilentlyContinue
                        Remove-Item Env:\BW_PASSWORD -ErrorAction SilentlyContinue
                    }
                }
                'Session'
                {
                    Write-VWLog -Message "Attempting to unlock vault with provided session key" -Level Verbose -Category Authentication
                    $env:BW_SESSION = $SessionKey
                    
                    # Verify the session is valid
                    $unlockOutput = & bw sync 2>&1
                    
                    # If successful, just store the session token
                    if ($unlockOutput -notmatch "error|failed|not found|invalid|unauthorized")
                    {
                        $sessionToken = $SessionKey
                    }
                }
                'Certificate'
                {
                    Write-VWLog -Message "Attempting to unlock vault with certificate authentication" -Level Verbose -Category Certificate
                    
                    # Check if certificate exists
                    if ($CertificateThumbprint)
                    {
                        $cert = Get-Item -Path "Cert:\CurrentUser\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
                        if (-not $cert)
                        {
                            throw "Certificate with thumbprint '$CertificateThumbprint' not found"
                        }
                        
                        # Use the bw CLI with certificate auth (depends on Bitwarden CLI version)
                        $unlockOutput = & bw unlock --auth-method certificate --auth-cert $CertificateThumbprint 2>&1
                        
                        # Extract session key if successful
                        if ($unlockOutput -match "BW_SESSION=`"(.+?)`"")
                        {
                            $sessionToken = $Matches[1]
                        }
                    }
                    else
                    {
                        throw "Certificate thumbprint is required when using certificate authentication"
                    }
                    catch
                    {
                        $errorMsg = "Failed to unlock vault using certificate."
                        # Pass the underlying Exception object from the ErrorRecord
                        Write-VWLog -Message $errorMsg -Level Error -Category Authentication -EventId 1004 -Exception $_.Exception 
                        throw $errorMsg
                    }
                }
            }
            
            # Check for unlock errors
            if (-not $sessionToken -or $unlockOutput -match "error|failed|not found|invalid|unauthorized")
            {
                throw "Failed to unlock Vaultwarden vault: $unlockOutput"
            }
            
            # Store the session key and update environment variable
            $env:BW_SESSION = $sessionToken
            
            # Initialize or update session tracking information
            $script:SessionInfo = @{
                LastUnlocked     = Get-Date
                ExpiresAt        = (Get-Date).AddMinutes($SessionTimeout)
                IsCacheValid     = $false
                LastCacheRefresh = $null
            }
            
            # Perform initial vault sync and cache data if enabled
            if ($EnableCache)
            {
                Write-VWLog -Message "Syncing vault data for caching" -Level Verbose -Category Cache
                
                # Use the Sync-VaultwardenState internal function for sync operations
                $syncSuccess = Sync-VaultwardenState -Force
                
                if ($syncSuccess)
                {
                    $script:SessionInfo.IsCacheValid = $true
                    $script:SessionInfo.LastCacheRefresh = Get-Date
                    Write-VWLog -Message "Successfully cached vault data" -Level Information -Category Cache
                }
            }
            
            # Verify unlock status
            $status = & bw status | ConvertFrom-Json
            if ($status.status -ne "unlocked")
            {
                throw "Failed to verify unlock status. Current status: $($status.status)"
            }
            
            # Output success message
            if (-not $NoStatus)
            {
                Write-Output "Successfully unlocked Vaultwarden vault. Session will expire in $SessionTimeout minutes."
            }
            
            Write-VWLog -Message "Vault successfully unlocked" -Level Information -Category Authentication -EventId 1003 -Data @{ 
                SessionExpiration = $script:SessionInfo.ExpiresAt
                CacheEnabled      = $EnableCache
            }
            
            return $true
        }
        catch
        {
            Write-VWLog -Message "Failed to unlock Vaultwarden vault" -Level Error -Category Authentication -EventId 1004 -Exception $_
            Write-Error "Failed to unlock Vaultwarden vault: $_"
            return $false
        }
    }
}