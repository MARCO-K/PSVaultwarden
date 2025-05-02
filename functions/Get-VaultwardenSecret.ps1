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
    
    .EXAMPLE
        $clientId = Get-VaultwardenSecret -Name "MgClientID" -AsPlainText
        
    .EXAMPLE
        $clientSecret = Get-VaultwardenSecret -Name "MgClientSecret"
        # Returns a secure string
        
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
        [switch]$AsPlainText
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
    }
    
    process {
        try {
            $params = @{
                Name = $Name
                Vault = $VaultName
            }
            
            if ($AsPlainText) {
                $params['AsPlainText'] = $true
            }
            
            Write-Verbose "Retrieving secret '$Name' from vault '$VaultName'"
            $secret = Get-Secret @params
            
            if ($null -eq $secret) {
                Write-Warning "Secret '$Name' not found in vault '$VaultName'"
                return $null
            }
            
            return $secret
        }
        catch {
            Write-Error "Failed to retrieve secret '$Name': $_"
            return $null
        }
    }
}
