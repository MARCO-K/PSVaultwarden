function Test-VaultwardenConnection
{
    <#
    .SYNOPSIS
        Tests the connection to Vaultwarden and validates vault accessibility.
    
    .DESCRIPTION
        This function tests the connection to a Vaultwarden instance by checking:
        1. Whether Bitwarden CLI is accessible
        2. If the user is authenticated with Vaultwarden
        3. If the registered vault is accessible and functional
    
    .PARAMETER VaultName
        The name of the registered SecretManagement vault to test. Defaults to "VaultwardenVault".
        
    .PARAMETER Detailed
        Returns a detailed status object instead of a boolean.
    
    .EXAMPLE
        Test-VaultwardenConnection
        # Returns: True if connected, False otherwise
        
    .EXAMPLE
        Test-VaultwardenConnection -Detailed
        # Returns detailed status object with Cli, Authentication, and Vault status
        
    .NOTES
        This function is useful for validating the environment before attempting to access secrets.
    #>
    
    [CmdletBinding()]
    [OutputType([bool], [PSCustomObject])]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$VaultName = $script:DefaultVaultName,
        
        [Parameter(Mandatory = $false)]
        [switch]$Detailed
    )
    
    # Initialize status object
    $status = [PSCustomObject]@{
        IsConnected    = $false
        Cli            = @{
            Available = $false
            Version   = $null
            Error     = $null
        }
        Authentication = @{
            Status = "unknown"
            Error  = $null
        }
        Vault          = @{
            Registered = $false
            Accessible = $false
            Error      = $null
        }
    }
    
    # Check if Bitwarden CLI is installed and accessible
    try
    {
        $cliVersion = & bw --version
        $status.Cli.Available = $true
        $status.Cli.Version = $cliVersion.Trim()
        Write-Verbose "Bitwarden CLI version: $($status.Cli.Version)"
    }
    catch
    {
        $status.Cli.Available = $false
        $status.Cli.Error = "Bitwarden CLI not found or inaccessible: $_"
        Write-Verbose $status.Cli.Error
        
        if ($Detailed)
        {
            return $status
        }
        return $false
    }
    
    # Check authentication status
    try
    {
        $authStatus = & bw status | ConvertFrom-Json
        $status.Authentication.Status = $authStatus.status
        
        if ($authStatus.status -eq "unlocked")
        {
            Write-Verbose "Vaultwarden authentication status: unlocked"
        }
        else
        {
            $status.Authentication.Error = "Not authenticated with Vaultwarden. Status: $($authStatus.status)"
            Write-Verbose $status.Authentication.Error
            
            if ($Detailed)
            {
                return $status
            }
            return $false
        }
    }
    catch
    {
        $status.Authentication.Status = "error"
        $status.Authentication.Error = "Error checking authentication status: $_"
        Write-Verbose $status.Authentication.Error
        
        if ($Detailed)
        {
            return $status
        }
        return $false
    }
    
    # Check if the vault is registered and accessible
    $vault = Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue
    if ($vault)
    {
        $status.Vault.Registered = $true
        Write-Verbose "Vault '$VaultName' is registered."
        
        try
        {
            # Attempt to get a non-existent secret to test accessibility without listing all
            # Listing all secrets (default behavior without -Name) can cause regex errors with some providers/versions
            Get-SecretInfo -Vault $VaultName -Name "PSVaultwarden-ConnectionTest-DoesNotExist" -ErrorAction Stop | Out-Null
            $status.Vault.Accessible = $true
            Write-Verbose "Vault '$VaultName' is accessible."
        }
        catch
        {
            $status.Vault.Accessible = $false
            # Provide a more specific error message based on the exception
            if ($_ -match "The argument to operator 'Imatch' is not valid")
            {
                $status.Vault.Error = "Vault '$VaultName' is registered but not accessible: Potential issue with SecretManagement wildcard handling. $_"
            }
            else
            {
                $status.Vault.Error = "Vault '$VaultName' is registered but not accessible: $_"
            }
            Write-Verbose $status.Vault.Error
        }
    }
    else
    {
        $status.Vault.Registered = $false
        $status.Vault.Error = "Vault '$VaultName' is not registered."
        Write-Verbose $status.Vault.Error
    }
    
    # If we got here, everything is working
    $status.IsConnected = $true
    
    if ($Detailed)
    {
        return $status
    }
    return $true
}
