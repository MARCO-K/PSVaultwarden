function Connect-MgGraphWithVault {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph using credentials stored in Vaultwarden.
    
    .DESCRIPTION
        This function retrieves Microsoft Graph authentication credentials from a Vaultwarden vault
        and uses them to establish a connection to the Microsoft Graph API. It supports both
        client credential flow and certificate-based authentication.
    
    .PARAMETER VaultName
        The name of the SecretManagement vault to use. Defaults to "VaultwardenVault".
    
    .PARAMETER ClientIdName
        The name of the secret containing the application (client) ID. Defaults to "MgClientID".
        
    .PARAMETER TenantIdName
        The name of the secret containing the tenant ID. Defaults to "MgTenantID".
        
    .PARAMETER ClientSecretName
        The name of the secret containing the client secret. Required for client secret authentication.
        Defaults to "MgClientSecret".
        
    .PARAMETER CertificateThumbprintName
        The name of the secret containing the certificate thumbprint. Used for certificate authentication.
        
    .PARAMETER Scopes
        Array of Microsoft Graph API permission scopes to request.
    
    .EXAMPLE
        Connect-MgGraphWithVault -Scopes "User.Read.All", "Directory.Read.All"
        # Connects using client secret stored in Vaultwarden
        
    .EXAMPLE
        Connect-MgGraphWithVault -CertificateThumbprintName "MgCertThumbprint" -Scopes "User.ReadWrite.All"
        # Connects using certificate-based authentication
        
    .NOTES
        You must have the Microsoft.Graph modules installed.
        The vault must contain the required secrets for authentication.
    #>
    
    [CmdletBinding(DefaultParameterSetName = 'ClientSecret')]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$VaultName = $script:DefaultVaultName,
        
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ClientIdName = "MgClientID",
        
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantIdName = "MgTenantID",
        
        [Parameter(Mandatory = $false, ParameterSetName = 'ClientSecret')]
        [ValidateNotNullOrEmpty()]
        [string]$ClientSecretName = "MgClientSecret",
        
        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateThumbprintName,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Scopes = @()
    )
    
    begin {
        # Check if Microsoft Graph modules are installed
        if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
            throw "Microsoft.Graph.Authentication module is not installed. Install it using: Install-Module -Name Microsoft.Graph.Authentication -Repository PSGallery"
        }
        
        # Verify connection to Vaultwarden
        $connected = Test-VaultwardenConnection -VaultName $VaultName
        if (-not $connected) {
            throw "Not connected to Vaultwarden or vault is inaccessible. Please run Connect-VaultwardenAPI and Register-VaultwardenVault first."
        }
    }
    
    process {
        try {
            # Retrieve application (client) ID from vault
            $clientId = Get-VaultwardenSecret -Name $ClientIdName -VaultName $VaultName -AsPlainText
            if (-not $clientId) {
                throw "Failed to retrieve application ID from secret '$ClientIdName'"
            }
            
            # Retrieve tenant ID from vault
            $tenantId = Get-VaultwardenSecret -Name $TenantIdName -VaultName $VaultName -AsPlainText
            if (-not $tenantId) {
                throw "Failed to retrieve tenant ID from secret '$TenantIdName'"
            }
            
            # Prepare connection parameters
            $connectParams = @{
                TenantId = $tenantId
                NoWelcome = $true
            }
            
            # Add scopes if specified
            if ($Scopes.Count -gt 0) {
                $connectParams['Scopes'] = $Scopes
            }
            
            # Connect using either client secret or certificate
            if ($PSCmdlet.ParameterSetName -eq 'ClientSecret') {
                # Retrieve client secret from vault
                $clientSecret = Get-VaultwardenSecret -Name $ClientSecretName -VaultName $VaultName -AsPlainText
                if (-not $clientSecret) {
                    throw "Failed to retrieve client secret from secret '$ClientSecretName'"
                }
                
                # Create secure credential
                $secureSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force
                $credential = New-Object System.Management.Automation.PSCredential($clientId, $secureSecret)
                
                # Add credential to parameters
                $connectParams['ClientSecretCredential'] = $credential
                
                Write-Verbose "Connecting to Microsoft Graph using client secret authentication"
            }
            else {
                # Retrieve certificate thumbprint from vault
                $certThumbprint = Get-VaultwardenSecret -Name $CertificateThumbprintName -VaultName $VaultName -AsPlainText
                if (-not $certThumbprint) {
                    throw "Failed to retrieve certificate thumbprint from secret '$CertificateThumbprintName'"
                }
                
                # Add certificate thumbprint to parameters
                $connectParams['ClientId'] = $clientId
                $connectParams['CertificateThumbprint'] = $certThumbprint
                
                Write-Verbose "Connecting to Microsoft Graph using certificate authentication"
            }
            
            # Connect to Microsoft Graph
            Connect-MgGraph @connectParams
            
            # Verify connection
            $context = Get-MgContext
            if ($context) {
                Write-Output "Connected to Microsoft Graph as application '$($context.AppName)' ($($context.AppId))"
                Write-Output "Authentication method: $($context.AuthType)"
                Write-Output "Tenant: $($context.TenantId)"
                
                if ($context.Scopes) {
                    Write-Output "Granted scopes: $($context.Scopes -join ', ')"
                }
                
                return $true
            }
            else {
                throw "Failed to verify Microsoft Graph connection"
            }
        }
        catch {
            Write-Error "Failed to connect to Microsoft Graph: $_"
            return $false
        }
    }
}
