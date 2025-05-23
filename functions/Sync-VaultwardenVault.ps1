function Sync-VaultwardenVault
{
    <#
    .SYNOPSIS
        Forces a synchronization of the Vaultwarden vault.
    
    .DESCRIPTION
        This function forces a synchronization of the Vaultwarden vault with the server.
        It ensures that any recently created or modified secrets are available for retrieval.
    
    .PARAMETER NoStatus
        Suppresses status output.
    
    .EXAMPLE
        Sync-VaultwardenVault
        
    .NOTES
        You must be connected to Vaultwarden via Connect-VaultwardenAPI before using this function.
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [switch]$NoStatus
    )
    
    try
    {
        # Verify that we're connected to Vaultwarden
        $status = & bw status | ConvertFrom-Json
        if ($status.status -ne "unlocked")
        {
            throw "Not authenticated with Vaultwarden or vault is locked. Please run Connect-VaultwardenAPI first."
        }
        
        # Perform the sync operation
        Write-Verbose "Forcing synchronization of the Vaultwarden vault"
        $syncOutput = & bw sync --force 2>&1
        
        if ($syncOutput -match "error|failed|not found|invalid")
        {
            throw "Failed to synchronize the vault: $syncOutput"
        }
        
        if (-not $NoStatus)
        {
            Write-Output "Vault synchronized successfully"
        }
        
        # Log if Write-VWLog is available
        if (Get-Command -Name Write-VWLog -ErrorAction SilentlyContinue)
        {
            Write-VWLog -Message "Vault synchronized successfully" -Level Information -Category Synchronization
        }
        
        return $true
    }
    catch
    {
        # Log if Write-VWLog is available
        if (Get-Command -Name Write-VWLog -ErrorAction SilentlyContinue)
        {
            Write-VWLog -Message "Failed to synchronize the vault: $_" -Level Error -Category Synchronization -EventId 1003 -Exception $_
        }
        
        Write-Error "Failed to synchronize the vault: $_"
        return $false
    }
}