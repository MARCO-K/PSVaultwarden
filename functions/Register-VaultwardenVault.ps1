function Register-VaultwardenVault {
    <#
    .SYNOPSIS
        Registers a Vaultwarden instance as a SecretManagement vault.
    
    .DESCRIPTION
        This function registers a Vaultwarden instance as a SecretManagement vault for use with
        PowerShell's SecretManagement module. It requires the SecretManagement.BitWarden module to be installed.
    
    .PARAMETER VaultName
        The name to use for the registered vault. Defaults to "VaultwardenVault".
    
    .PARAMETER VaultwardenUrl
        The URL of your Vaultwarden instance. If not specified, uses the current BW_URL environment variable.
        
    .PARAMETER Force
        Forces re-registration of the vault even if it already exists.
        
    .PARAMETER AutoSync
        Enables automatic synchronization of the vault. Defaults to $true.
    
    .EXAMPLE
        Register-VaultwardenVault -VaultName "CompanyVault" -VaultwardenUrl "https://vault.example.com"
        
    .NOTES
        This function requires the SecretManagement.BitWarden module to be installed.
        You must be connected to Vaultwarden via Connect-VaultwardenAPI before using this function.
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$VaultName = $script:DefaultVaultName,
        
        [Parameter(Mandatory = $false)]
        [ValidatePattern('^https?://')]
        [string]$VaultwardenUrl = $env:BW_URL,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        
        [Parameter(Mandatory = $false)]
        [bool]$AutoSync = $true
    )
    
    begin {
        # Check if SecretManagement.BitWarden module is installed
        if (-not (Get-Module -ListAvailable -Name 'SecretManagement.BitWarden')) {
            throw "SecretManagement.BitWarden module is not installed. Install it using: Install-Module -Name SecretManagement.BitWarden -Repository PSGallery"
        }
        
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
        
        # Check if VaultwardenUrl is specified or available in environment
        if (-not $VaultwardenUrl) {
            throw "VaultwardenUrl is not specified and BW_URL environment variable is not set."
        }
    }
    
    process {
        try {
            # Check if vault already exists
            $existingVault = Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue
            
            if ($existingVault -and -not $Force) {
                Write-Warning "Vault '$VaultName' already exists. Use -Force to re-register."
                return $false
            }
            
            # Unregister if it exists and Force is specified
            if ($existingVault -and $Force) {
                Write-Verbose "Unregistering existing vault: $VaultName"
                Unregister-SecretVault -Name $VaultName
            }
            
            # Register the vault
            $vaultParams = @{
                VaultUrl = $VaultwardenUrl
                Sync = $AutoSync
            }
            
            Write-Verbose "Registering Vaultwarden as SecretManagement vault: $VaultName"
            Register-SecretVault -Name $VaultName -ModuleName 'SecretManagement.BitWarden' -VaultParameters $vaultParams
            
            # Verify registration
            $vault = Get-SecretVault -Name $VaultName -ErrorAction Stop
            if ($vault) {
                Write-Output "Successfully registered Vaultwarden vault: $VaultName"
                return $true
            }
            else {
                throw "Failed to verify vault registration"
            }
        }
        catch {
            Write-Error "Failed to register Vaultwarden vault: $_"
            return $false
        }
    }
}
