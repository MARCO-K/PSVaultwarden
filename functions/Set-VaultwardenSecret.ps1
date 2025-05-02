function Set-VaultwardenSecret
{
    <#
    .SYNOPSIS
        Adds or updates a secret in the Vaultwarden vault.
    
    .DESCRIPTION
        This function adds a new secret to the Vaultwarden vault or updates an existing one.
        It supports various types of secrets including login credentials, secure notes, and card information.
        The vault must be unlocked before using this function.
    
    .PARAMETER Name
        The name of the secret to add or update.
        
    .PARAMETER SecureStringValue
        The secret value as a SecureString.
        
    .PARAMETER Notes
        Optional notes to add to the secret.
        
    .PARAMETER VaultName
        The name of the registered SecretManagement vault. Defaults to "VaultwardenVault".
        
    .PARAMETER Uri
        Optional URI associated with the secret (useful for login items).
        
    .PARAMETER Username
        Optional username associated with the secret (for login items).
        
    .PARAMETER Type
        The type of item to create. Default is 'Login'.
        Valid values: Login, SecureNote, Card, Identity
        
    .PARAMETER Force
        Overwrites the secret if it already exists.
        
    .PARAMETER PassThru
        Returns the created/updated secret object.
        
    .PARAMETER Tags
        Optional tags to assign to the secret.
        
    .PARAMETER SkipMetadata
        If specified, does not attempt to add metadata to the secret.
        Use this when working with vaults that don't support metadata operations.
        
    .EXAMPLE
        $securePassword = ConvertTo-SecureString "MySecurePassword" -AsPlainText -Force
        Set-VaultwardenSecret -Name "MyAppLogin" -SecureStringValue $securePassword -Username "user@example.com" -Uri "https://example.com"
        
    .EXAMPLE
        $secureNote = ConvertTo-SecureString "This is a secure note" -AsPlainText -Force
        Set-VaultwardenSecret -Name "Important Note" -SecureStringValue $secureNote -Type SecureNote
        
    .EXAMPLE
        $securePassword = ConvertTo-SecureString "MySecurePassword" -AsPlainText -Force
        Set-VaultwardenSecret -Name "BasicSecret" -SecureStringValue $securePassword -SkipMetadata
        
    .NOTES
        The vault must be unlocked using Unlock-VaultwardenVault before using this function.
        Some vaults might not support metadata operations, in which case use the -SkipMetadata switch.
    #>
    
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNull()]
        [System.Security.SecureString]$SecureStringValue,
        
        [Parameter(Mandatory = $false)]
        [string]$Notes,
        
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$VaultName = $script:DefaultVaultName,
        
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Uri,
        
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Username,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Login', 'SecureNote', 'Card', 'Identity')]
        [string]$Type = 'Login',
        
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        
        [Parameter(Mandatory = $false)]
        [switch]$PassThru,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Tags,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipMetadata
    )
    
    begin
    {
        # Verify connection to Vaultwarden
        $vaultTest = Test-VaultwardenConnection -VaultName $VaultName -Detailed
        
        if (-not $vaultTest.IsConnected)
        {
            $errorMsg = "Not connected to Vaultwarden or vault is not unlocked. Please run Connect-VaultwardenAPI and Unlock-VaultwardenVault first."
            Write-VWLog -Message $errorMsg -Level Error -Category Vault -EventId 2001
            throw $errorMsg
        }
        
        # Check if the secret already exists
        $existingSecret = $null
        try
        {
            $existingSecret = Get-SecretInfo -Name $Name -Vault $VaultName -ErrorAction SilentlyContinue
        }
        catch
        {
            # Secret doesn't exist, which is fine for creating a new one
            Write-VWLog -Message "No existing secret found with name '$Name'" -Level Verbose -Category Vault
        }
        
        if ($existingSecret -and -not $Force)
        {
            $errorMsg = "Secret '$Name' already exists. Use -Force to overwrite."
            Write-VWLog -Message $errorMsg -Level Warning -Category Vault -EventId 2002
            throw $errorMsg
        }
        
        # Check if the vault supports metadata operations if we're not skipping them
        if (-not $SkipMetadata)
        {
            try
            {
                # Test if the vault supports metadata by checking available commands for the vault extension
                $vaultExt = Get-SecretVault -Name $VaultName -ErrorAction Stop
                $vaultExtModule = Get-Module -Name $vaultExt.ModuleName -ErrorAction SilentlyContinue
                
                # Check if Set-SecretInfo is available
                $supportsMetadata = $null -ne ($vaultExtModule.ExportedCommands.Keys | Where-Object { $_ -eq 'Set-SecretInfo' })
                
                if (-not $supportsMetadata)
                {
                    Write-VWLog -Message "Vault '$VaultName' does not support metadata operations. Will store secret without metadata." -Level Warning -Category Vault
                    $SkipMetadata = $true
                }
            }
            catch
            {
                Write-VWLog -Message "Could not determine if vault '$VaultName' supports metadata operations. Will try anyway." -Level Warning -Category Vault
            }
        }
    }
    
    process
    {
        try
        {
            # Log the action we're about to take
            $action = if ($existingSecret) { "Updating" } else { "Creating" }
            Write-VWLog -Message "$action secret '$Name' in vault '$VaultName'" -Level Verbose -Category Vault
            
            # Convert SecureString to plain text (only happens in memory)
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureStringValue)
            $plainTextValue = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            
            try
            {
                # Prepare metadata based on the type of secret
                $metadata = @{}
                
                if (-not $SkipMetadata)
                {
                    switch ($Type)
                    {
                        'Login'
                        {
                            if ($Username) { $metadata['Username'] = $Username }
                            if ($Uri) { $metadata['Uri'] = $Uri }
                        }
                        'SecureNote'
                        {
                            $metadata['Type'] = 'SecureNote'
                        }
                        'Card'
                        {
                            $metadata['Type'] = 'Card'
                        }
                        'Identity'
                        {
                            $metadata['Type'] = 'Identity'
                        }
                    }
                    
                    if ($Notes)
                    {
                        $metadata['Notes'] = $Notes
                    }
                    
                    if ($Tags -and $Tags.Count -gt 0)
                    {
                        $metadata['Tags'] = $Tags -join ','
                    }
                }
                
                # Prepare for WhatIf support
                $WhatIfDescription = "$action secret '$Name' in vault '$VaultName'"
                
                if ($PSCmdlet.ShouldProcess($WhatIfDescription))
                {
                    # Store the secret in the vault
                    if ($existingSecret -and $Force)
                    {
                        # Update existing secret
                        if ($SkipMetadata)
                        {
                            Set-Secret -Name $Name -Vault $VaultName -Secret $plainTextValue -ErrorAction Stop
                        }
                        else
                        {
                            try
                            {
                                Set-Secret -Name $Name -Vault $VaultName -Secret $plainTextValue -Metadata $metadata -ErrorAction Stop
                            }
                            catch
                            {
                                # If metadata fails, try without it
                                Write-VWLog -Message "Could not set secret with metadata, trying without: $_" -Level Warning -Category Vault
                                Set-Secret -Name $Name -Vault $VaultName -Secret $plainTextValue -ErrorAction Stop
                            }
                        }
                        Write-VWLog -Message "Updated existing secret '$Name' in vault '$VaultName'" -Level Information -Category Vault -EventId 2003
                    }
                    else
                    {
                        # Create new secret
                        if ($SkipMetadata)
                        {
                            Set-Secret -Name $Name -Vault $VaultName -Secret $plainTextValue -ErrorAction Stop
                        }
                        else
                        {
                            try
                            {
                                Set-Secret -Name $Name -Vault $VaultName -Secret $plainTextValue -Metadata $metadata -ErrorAction Stop
                            }
                            catch
                            {
                                # If metadata fails, try without it
                                Write-VWLog -Message "Could not set secret with metadata, trying without: $_" -Level Warning -Category Vault
                                Set-Secret -Name $Name -Vault $VaultName -Secret $plainTextValue -ErrorAction Stop
                            }
                        }
                        Write-VWLog -Message "Created new secret '$Name' in vault '$VaultName'" -Level Information -Category Vault -EventId 2004
                    }
                    
                    # For vaults that support Set-SecretInfo independently, try to set metadata separately if needed
                    if (-not $SkipMetadata -and $metadata.Count -gt 0)
                    {
                        try
                        {
                            # Check if Set-SecretInfo command exists in the PowerShell session
                            if (Get-Command -Name Set-SecretInfo -ErrorAction SilentlyContinue)
                            {
                                Set-SecretInfo -Name $Name -Vault $VaultName -Metadata $metadata -ErrorAction SilentlyContinue
                            }
                        }
                        catch
                        {
                            Write-VWLog -Message "Failed to set metadata for secret '$Name': $_" -Level Warning -Category Vault
                            # This is non-fatal, we continue
                        }
                    }
                    
                    # Special handling for Username and URI in Vaultwarden
                    # If the metadata approach didn't work, try to use direct Bitwarden CLI for additional fields
                    if (-not $SkipMetadata -and (($Username -and $Type -eq 'Login') -or $Uri -or $Notes))
                    {
                        try
                        {
                            # Get the item to update
                            $itemSearch = & bw get item $Name 2>&1
                            
                            if ($itemSearch -and ($itemSearch | ConvertFrom-Json -ErrorAction Stop))
                            {
                                $item = $itemSearch | ConvertFrom-Json -ErrorAction Stop
                                
                                # Set additional fields via CLI if the item exists
                                if ($item.id)
                                {
                                    # Create an edit template
                                    $editTemplate = & bw get item $item.id | ConvertFrom-Json -ErrorAction Stop
                                    
                                    if ($Type -eq 'Login')
                                    {
                                        if (-not $editTemplate.login)
                                        {
                                            $editTemplate.login = @{}
                                        }
                                        
                                        if ($Username)
                                        {
                                            $editTemplate.login.username = $Username
                                        }
                                        
                                        if ($Uri)
                                        {
                                            if (-not $editTemplate.login.uris)
                                            {
                                                $editTemplate.login.uris = @()
                                            }
                                            
                                            # Only add URI if it doesn't exist
                                            $uriExists = $false
                                            foreach ($existingUri in $editTemplate.login.uris)
                                            {
                                                if ($existingUri.uri -eq $Uri)
                                                {
                                                    $uriExists = $true
                                                    break
                                                }
                                            }
                                            
                                            if (-not $uriExists)
                                            {
                                                $editTemplate.login.uris += @{
                                                    match = $null
                                                    uri   = $Uri
                                                }
                                            }
                                        }
                                    }
                                    
                                    if ($Notes)
                                    {
                                        $editTemplate.notes = $Notes
                                    }
                                    
                                    # Apply the edit
                                    $editJson = $editTemplate | ConvertTo-Json -Depth 10 -Compress
                                    $encodedJson = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($editJson))
                                    
                                    & bw edit item $item.id $encodedJson | Out-Null
                                    Write-VWLog -Message "Updated additional fields for secret '$Name' using direct CLI" -Level Verbose -Category Vault
                                }
                            }
                        }
                        catch
                        {
                            Write-VWLog -Message "Failed to set additional fields via CLI for '$Name': $_" -Level Warning -Category Vault
                            # This is non-fatal, we continue
                        }
                    }
                    
                    # Sync the vault state
                    $syncSuccess = Sync-VaultwardenState
                    
                    if (-not $syncSuccess)
                    {
                        Write-VWLog -Message "Warning: Vault sync after adding/updating secret may have failed" -Level Warning -Category Vault
                    }
                    
                    # Return the secret if PassThru is specified
                    if ($PassThru)
                    {
                        Get-SecretInfo -Name $Name -Vault $VaultName
                    }
                }
            }
            finally
            {
                # Securely clear the plain text value
                if ($BSTR -ne [IntPtr]::Zero)
                {
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
                }
                Remove-Variable -Name plainTextValue -ErrorAction SilentlyContinue
            }
        }
        catch
        {
            Write-VWLog -Message "Failed to set secret '$Name' in vault '$VaultName'" -Level Error -Category Vault -EventId 2005 -Exception $_.Exception
            throw $_
        }
    }
    
    end
    {
        # Nothing to do in the end block
    }
}