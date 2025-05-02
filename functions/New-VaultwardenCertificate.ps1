function New-VaultwardenCertificate {
    <#
    .SYNOPSIS
        Creates or imports a certificate for Vaultwarden authentication.
    
    .DESCRIPTION
        This function either creates a new self-signed certificate or imports an existing certificate
        for use with Vaultwarden certificate-based authentication. It securely stores the certificate
        in the user's certificate store and optionally in the Vaultwarden vault itself.
    
    .PARAMETER Subject
        The certificate subject name, typically in the format "CN=VaultwardenAuth".
        
    .PARAMETER CertPath
        Path to an existing certificate file (.pfx) to import.
        
    .PARAMETER CertPassword
        Password for the certificate file as a SecureString.
        
    .PARAMETER ExpiryMonths
        Number of months until the certificate expires for new certificates. Default is 12.
        
    .PARAMETER KeyLength
        Key length for new certificates. Default is 2048.
        
    .PARAMETER StoreLocation
        Certificate store location. Default is CurrentUser.
        
    .PARAMETER StoreName
        Certificate store name. Default is My (Personal).
        
    .PARAMETER StoreInVault
        Store certificate details in the Vaultwarden vault for future reference.
        
    .PARAMETER VaultName
        The name of the SecretManagement vault to use if storing in vault.
        
    .PARAMETER SecretName
        The name to use for the certificate secret if storing in vault.
        
    .PARAMETER Force
        Overwrite existing certificate with same subject name.
    
    .EXAMPLE
        New-VaultwardenCertificate -Subject "CN=VaultwardenAuth" -StoreInVault
        
    .EXAMPLE
        $certPass = Read-Host -AsSecureString -Prompt "Certificate Password"
        New-VaultwardenCertificate -CertPath "C:\certs\vaultwarden.pfx" -CertPassword $certPass
        
    .NOTES
        Certificate-based authentication provides stronger security than password-based authentication.
        The certificate private key is protected by the Windows certificate store security mechanisms.
    #>
    
    [CmdletBinding(DefaultParameterSetName = 'Create')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Create')]
        [ValidateNotNullOrEmpty()]
        [string]$Subject = "CN=VaultwardenAuth",
        
        [Parameter(Mandatory = $true, ParameterSetName = 'Import')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$CertPath,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'Import')]
        [ValidateNotNull()]
        [System.Security.SecureString]$CertPassword,
        
        [Parameter(Mandatory = $false, ParameterSetName = 'Create')]
        [ValidateRange(1, 120)]
        [int]$ExpiryMonths = 12,
        
        [Parameter(Mandatory = $false, ParameterSetName = 'Create')]
        [ValidateSet(2048, 4096)]
        [int]$KeyLength = 2048,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [string]$StoreLocation = 'CurrentUser',
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('My', 'Root', 'AddressBook', 'AuthRoot', 'TrustedPeople')]
        [string]$StoreName = 'My',
        
        [Parameter(Mandatory = $false)]
        [switch]$StoreInVault,
        
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$VaultName = $script:DefaultVaultName,
        
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$SecretName = "VaultwardenCertificate",
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    begin {
        # Check if we're connected to Vaultwarden if we need to store in vault
        if ($StoreInVault) {
            try {
                $status = & bw status | ConvertFrom-Json
                if ($status.status -ne "unlocked") {
                    throw "Not authenticated with Vaultwarden. Please run Connect-VaultwardenAPI and Unlock-VaultwardenVault first."
                }
                
                # Check if vault exists
                $vault = Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue
                if (-not $vault) {
                    throw "Vault '$VaultName' does not exist. Please register it using Register-VaultwardenVault."
                }
            }
            catch {
                Write-VWLog -Message "Failed to verify Vaultwarden connection for certificate storage" -Level Error -Category Certificate -EventId 2001 -Exception $_
                throw "Failed to verify Vaultwarden connection: $_"
            }
        }
    }
    
    process {
        try {
            # Initialize certificate store
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($StoreName, $StoreLocation)
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            
            # Check if certificate with same subject already exists
            $existingCerts = $store.Certificates | Where-Object { $_.Subject -eq $Subject }
            if ($existingCerts -and -not $Force) {
                throw "Certificate with subject '$Subject' already exists. Use -Force to overwrite."
            }
            elseif ($existingCerts -and $Force) {
                Write-VWLog -Message "Removing existing certificate with subject '$Subject'" -Level Warning -Category Certificate
                foreach ($cert in $existingCerts) {
                    $store.Remove($cert)
                }
            }
            
            # Create or import the certificate
            $certificate = $null
            
            if ($PSCmdlet.ParameterSetName -eq 'Create') {
                Write-VWLog -Message "Creating new self-signed certificate for Vaultwarden authentication" -Level Information -Category Certificate
                
                # Calculate expiry date
                $notAfter = (Get-Date).AddMonths($ExpiryMonths)
                
                # Create a new self-signed certificate
                $cert = New-SelfSignedCertificate -Subject $Subject -KeyAlgorithm RSA -KeyLength $KeyLength `
                    -NotAfter $notAfter -CertStoreLocation "Cert:\$StoreLocation\$StoreName" `
                    -KeyUsage DigitalSignature, KeyEncipherment -FriendlyName "Vaultwarden Authentication" `
                    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2") # Client Authentication EKU
                
                $certificate = $cert
                Write-VWLog -Message "Created new certificate with thumbprint '$($cert.Thumbprint)'" -Level Information -Category Certificate
            }
            else {
                Write-VWLog -Message "Importing certificate from '$CertPath'" -Level Information -Category Certificate
                
                # Import the certificate from the PFX file
                $importParams = @{
                    FilePath = $CertPath
                    Password = $CertPassword
                    CertStoreLocation = "Cert:\$StoreLocation\$StoreName"
                }
                
                $certificate = Import-PfxCertificate @importParams
                Write-VWLog -Message "Imported certificate with thumbprint '$($certificate.Thumbprint)'" -Level Information -Category Certificate
            }
            
            # Store the certificate information in the vault if requested
            if ($StoreInVault) {
                Write-VWLog -Message "Storing certificate information in Vaultwarden vault" -Level Verbose -Category Certificate
                
                # Create a hashtable with certificate details
                $certInfo = @{
                    Thumbprint = $certificate.Thumbprint
                    Subject = $certificate.Subject
                    Issuer = $certificate.Issuer
                    NotBefore = $certificate.NotBefore.ToString('o')
                    NotAfter = $certificate.NotAfter.ToString('o')
                    SerialNumber = $certificate.SerialNumber
                    StoreLocation = $StoreLocation
                    StoreName = $StoreName
                    CreatedDate = (Get-Date).ToString('o')
                }
                
                # Convert to secure string and store in vault
                $certInfoJson = $certInfo | ConvertTo-Json -Compress
                $secureValue = ConvertTo-SecureString $certInfoJson -AsPlainText -Force
                
                Set-Secret -Name $SecretName -Vault $VaultName -Secret $secureValue
                Write-VWLog -Message "Certificate information stored in vault as '$SecretName'" -Level Information -Category Certificate
            }
            
            # Output the certificate details
            $result = [PSCustomObject]@{
                Thumbprint = $certificate.Thumbprint
                Subject = $certificate.Subject
                Issuer = $certificate.Issuer
                NotBefore = $certificate.NotBefore
                NotAfter = $certificate.NotAfter
                StorePath = "Cert:\$StoreLocation\$StoreName\$($certificate.Thumbprint)"
                InVault = $StoreInVault
                VaultSecretName = if ($StoreInVault) { $SecretName } else { $null }
            }
            
            Write-Output $result
            return $result
        }
        catch {
            Write-VWLog -Message "Failed to create or import certificate" -Level Error -Category Certificate -EventId 2002 -Exception $_
            Write-Error "Failed to create or import certificate: $_"
            return $null
        }
        finally {
            # Always close the certificate store
            if ($store) {
                $store.Close()
            }
        }
    }
}