# 1. core

I need to plan a scenario for powershell scripts which will use the ms graph api

## 2. Scenario

I need to ensure that no secrets are in the scripts. that's why i want to use my own vaultwarden instance, which is connectable via internet.

- The scripts should use only secret stored in the vault.
- my scripts will also run automatically, that means the secret has to be accessible without manual interaction.
- I want to use the an API key to connect to vaultwarden

## 3. Requirements

- Important: no manual interaction for accessing secrets

- install the Bitwarden CLI and configure it to connect to their instance if necessary
- installing necessary PowerShell modules (SecretManagement and SecretManagement.BitWarden) if necesarry
- using the API key to connect to vaultwarden

## 4. further information

They need to store their client ID, tenant ID, and client secret in Vaultwarden.
Then, in the script, retrieve these secrets using Get-Secret.
But how to authenticate the CLI without manual interaction?
They'll need to use an API key or client credentials for Vaultwarden.
Maybe set environment variables for BW_CLIENTID and BW_CLIENTSECRET so the CLI can authenticate automatically.

### 4.1 Environment Protection

- Secure the Service Account:
- Use API Key authentication instead of master password
- Restrict to read-only access for the specific collection
- Rotate Secrets
- Certificate-Based Authentication (Recommended)
- Monitoring & Maintenance
- Automatic Token Renewal

## 5. Schema

graph TD
    A[PowerShell Script] -->|Retrieves Secrets| B(Vaultwarden)
    B -->|Returns Credentials| A
    A -->|Authenticates| C[Microsoft Graph API]

# 6. Key Advantages

Zero Secrets in Code: All credentials stored in Vaultwarden

Central Management: Single source of truth for secrets

Audit Trail: Track secret access through Vaultwarden logs

Automatic Rotation: Update secrets in Vaultwarden without changing scripts

# 7. Technical Details

## 7.1 Prerequisites

- PowerShell 5.1 or later (PowerShell 7.x recommended for cross-platform support)
- Bitwarden CLI installed and accessible from PATH
- Vaultwarden instance deployed and accessible via HTTPS
- API key generated for the Vaultwarden instance
- PowerShell modules:
  - SecretManagement (1.1.2 or later)
  - SecretManagement.BitWarden (1.1.0 or later)
  - Microsoft.Graph modules as needed by scripts

## 7.2 Module Structure

```
PSVaultwarden/
├── PSVaultwarden.psd1          # Module manifest
├── PSVaultwarden.psm1          # Main module file
├── functions/                  # Public functions
│   ├── Connect-VaultwardenAPI.ps1      # Handle API authentication
│   ├── Get-VaultwardenSecret.ps1       # Retrieve secrets 
│   ├── Register-VaultwardenVault.ps1   # Register Vaultwarden as secret vault
│   ├── Test-VaultwardenConnection.ps1  # Verify connectivity
│   └── Connect-MgGraphWithVault.ps1    # Connect to Graph using secrets
└── internal/                   # Private helper functions
    ├── Initialize-Environment.ps1      # Set up environment variables
    └── Sync-VaultwardenState.ps1      # Force vault synchronization
```

## 7.3 Authentication Flow

1. **Initial Setup (one-time)**:
   - Generate API key in Vaultwarden web interface
   - Store API credentials securely (e.g., environment variables or config file)
   - Register Vaultwarden as a SecretManagement vault

2. **Automated Authentication**:
   - Set environment variables: `BW_CLIENTID`, `BW_CLIENTSECRET`, `BW_URL`
   - Authenticate with Bitwarden CLI using API key
   - Unlock vault using session key
   - Retrieve and use secrets in scripts

## 7.4 Security Considerations

- **Key Storage**: Store API keys in secure locations (Azure Key Vault, environment variables, etc.)
- **Read-Only Access**: Create dedicated service account with minimal permissions
- **Network Security**: Ensure Vaultwarden is accessible only through HTTPS
- **Session Management**: Minimize session duration; re-authenticate as needed
- **IP Restrictions**: Limit API access to specific IP addresses if possible
- **Audit Logging**: Enable comprehensive logging for all secret access operations

## 7.5 Implementation Examples

### 7.5.1 Initialization Script

```powershell
# Initialize Vaultwarden connection
function Initialize-VaultwardenConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VaultwardenUrl,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        
        [Parameter(Mandatory = $true)]
        [SecureString]$ClientSecret,
        
        [Parameter(Mandatory = $false)]
        [string]$VaultName = "CompanyVault"
    )
    
    # Set environment variables for CLI authentication
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret)
    $env:BW_CLIENTSECRET = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    $env:BW_CLIENTID = $ClientId
    $env:BW_URL = $VaultwardenUrl
    
    # Configure CLI to use custom server
    & bw config server $VaultwardenUrl
    
    # Log in using API key (non-interactive)
    $loginResult = & bw login --apikey
    
    # Register as SecretManagement vault
    if (Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue) {
        Unregister-SecretVault -Name $VaultName
    }
    
    Register-SecretVault -Name $VaultName -ModuleName SecretManagement.BitWarden -VaultParameters @{
        VaultUrl = $VaultwardenUrl
        Sync = $true
    }
    
    # Verify connection
    $status = & bw status | ConvertFrom-Json
    if ($status.status -ne "unlocked") {
        throw "Failed to unlock Vaultwarden vault"
    }
    
    Write-Output "Vaultwarden connection initialized successfully"
}
```

### 7.5.2 Microsoft Graph Connection

```powershell
function Connect-MgGraphWithVault {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$VaultName = "CompanyVault",
        
        [Parameter(Mandatory = $false)]
        [string]$ClientIdName = "MgClientID",
        
        [Parameter(Mandatory = $false)]
        [string]$TenantIdName = "MgTenantID",
        
        [Parameter(Mandatory = $false)]
        [string]$ClientSecretName = "MgClientSecret",
        
        [Parameter(Mandatory = $false)]
        [string[]]$Scopes = @()
    )
    
    # Retrieve secrets from vault
    $clientId = Get-Secret -Name $ClientIdName -Vault $VaultName -AsPlainText
    $tenantId = Get-Secret -Name $TenantIdName -Vault $VaultName -AsPlainText
    $clientSecret = Get-Secret -Name $ClientSecretName -Vault $VaultName -AsPlainText
    
    # Convert to secure credential
    $secureSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($clientId, $secureSecret)
    
    # Connect to Microsoft Graph
    Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $credential -Scopes $Scopes
    
    Write-Output "Connected to Microsoft Graph using credentials from Vaultwarden"
}
```

## 7.6 Automated Script Example

```powershell
# Example script showing full automation workflow
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = "$PSScriptRoot\config.json"
)

# Import modules
Import-Module PSVaultwarden
Import-Module Microsoft.Graph.Beta.Users

# Read configuration (contains URL and encrypted client ID)
$config = Get-Content $ConfigPath | ConvertFrom-Json

# Initialize Vaultwarden connection using environment variables or config
Initialize-VaultwardenConnection `
    -VaultwardenUrl $config.VaultwardenUrl `
    -ClientId $env:BW_CLIENTID `
    -ClientSecret (ConvertTo-SecureString $env:BW_CLIENTSECRET -AsPlainText -Force)

# Connect to Microsoft Graph using vault credentials
Connect-MgGraphWithVault -Scopes "User.Read.All", "Directory.Read.All"

# Execute Graph operations using credentials from vault
$users = Get-MgBetaUser -Top 10
$users | Select-Object DisplayName, UserPrincipalName

# Clean up (optional)
Disconnect-MgGraph
Remove-Item env:\BW_CLIENTSECRET
```

## 7.7 Error Handling and Resilience

- Implement connectivity checks before operations
- Handle authentication failures with graceful retry logic
- Cache authentication tokens where appropriate
- Implement proper exception handling for credential access failures
- Use logging to track authentication events and failures
- Consider implementing a fallback mechanism for critical operations

## 7.8 Monitoring and Maintenance

- Implement credential rotation schedule (90-day recommended)
- Log all secret access attempts for audit purposes
- Monitor for unusual access patterns or failures
- Implement alerting for authentication failures
- Schedule regular vault synchronization
- Verify vault accessibility from automation environments