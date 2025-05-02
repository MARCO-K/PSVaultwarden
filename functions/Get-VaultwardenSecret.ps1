function Get-VaultwardenSecret {
    <#
    .SYNOPSIS
        Retrieves a secret from the Vaultwarden vault.
    
    .DESCRIPTION
        This function retrieves a secret from the registered Vaultwarden vault.
        It wraps the SecretManagement Get-Secret cmdlet with additional validation and error handling.
    
    .PARAMETER Name
        The name of the secret to retrieve.
    
    .PARAMETER VaultName
        The name of the SecretManagement vault to use. Defaults to "VaultwardenVault".
        
    .PARAMETER AsPlainText
        Returns the secret as plain text instead of a SecureString.
        
    .PARAMETER SyncFirst
        Forces a synchronization of the vault before retrieving the secret.
    
    .EXAMPLE
        $clientId = Get-VaultwardenSecret -Name "MgClientID" -AsPlainText
        
    .EXAMPLE
        $clientSecret = Get-VaultwardenSecret -Name "MgClientSecret"
        # Returns a secure string
        
    .EXAMPLE
        $tenantId = Get-VaultwardenSecret -Name "tenantID" -SyncFirst
        # Synchronizes the vault before attempting to retrieve the secret
        
    .NOTES
        You must be connected to Vaultwarden via Connect-VaultwardenAPI and
        have registered the vault using Register-VaultwardenVault before using this function.
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$VaultName = $script:DefaultVaultName,
        
        [Parameter(Mandatory = $false)]
        [switch]$AsPlainText,
        
        [Parameter(Mandatory = $false)]
        [switch]$SyncFirst
    )
    
    begin {
        # Verify that we're connected to Vaultwarden
        try {
            $status = & bw status | ConvertFrom-Json
            if ($status.status -ne "unlocked") {
                throw "Not authenticated with Vaultwarden. Please run Connect-VaultwardenAPI first."
            }
        }
        catch {
            throw "Failed to check Vaultwarden status: $_. Make sure you're connected using Connect-VaultwardenAPI."
        }
        
        # Check if vault exists
        $vault = Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue
        if (-not $vault) {
            throw "Vault '$VaultName' does not exist. Please register it using Register-VaultwardenVault."
        }
        
        # Synchronize the vault first if requested
        if ($SyncFirst) {
            Write-Verbose "Synchronizing vault before retrieving secret"
            try {
                if (Get-Command -Name Sync-VaultwardenVault -ErrorAction SilentlyContinue) {
                    Sync-VaultwardenVault -NoStatus | Out-Null
                } else {
                    Write-Verbose "Performing synchronization with bw sync"
                    & bw sync --force | Out-Null
                }
            }
            catch {
                Write-Warning "Failed to synchronize the vault: $_. Continuing with retrieval attempt."
            }
        }
    }
    
    process {
        # First attempt to retrieve the secret
        try {
            $params = @{
                Name = $Name
                Vault = $VaultName
            }
            
            if ($AsPlainText) {
                $params['AsPlainText'] = $true
            }
            
            Write-Verbose "Retrieving secret '$Name' from vault '$VaultName'"
            $secret = Get-Secret @params -ErrorAction Stop
            
            if ($null -ne $secret) {
                return $secret
            }
        }
        catch {
            Write-Verbose "Initial secret retrieval attempt failed: $_"
            # Continue to fallback approaches
        }
        
        # If secret was not found, try synchronization as a fallback
        if (-not $SyncFirst) {
            Write-Verbose "Secret not found on first attempt, trying with synchronization"
            try {
                if (Get-Command -Name Sync-VaultwardenVault -ErrorAction SilentlyContinue) {
                    Sync-VaultwardenVault -NoStatus | Out-Null
                } else {
                    Write-Verbose "Performing fallback synchronization with bw sync"
                    & bw sync --force | Out-Null
                }
                
                # Try again after sync
                $secret = Get-Secret @params -ErrorAction SilentlyContinue
                
                if ($null -ne $secret) {
                    return $secret
                }
            }
            catch {
                Write-Verbose "Fallback synchronization failed: $_"
            }
        }
        
        # If we got here, the secret wasn't found even after sync attempts
        Write-Warning "Secret '$Name' not found in vault '$VaultName'"
        return $null
    }
}
