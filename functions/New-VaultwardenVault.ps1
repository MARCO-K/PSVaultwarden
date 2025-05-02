function New-VaultwardenVault
{
    <#
    .SYNOPSIS
        Creates a new vault (folder) in Vaultwarden.
    
    .DESCRIPTION
        This function creates a new vault (implemented as a folder) in the Vaultwarden instance.
        It checks if the folder already exists before attempting creation.
        The vault must be unlocked to create a new vault within Vaultwarden.
    
    .PARAMETER VaultName
        The name of the new vault (folder) to create.
        
    .PARAMETER Description
        Optional description for the new vault (stored as metadata).
        
    .PARAMETER Force
        If specified, will recreate the vault if it already exists.
        
    .PARAMETER DefaultVault
        If specified, marks this vault as the default vault.
    
    .PARAMETER PassThru
        If specified, returns the created vault object.
        
    .PARAMETER RegisterVault
        If specified, automatically registers the vault with SecretManagement.
        Defaults to $true.
    
    .EXAMPLE
        New-VaultwardenVault -VaultName "ProjectXVault" -Description "Credentials for Project X"
        
    .EXAMPLE
        New-VaultwardenVault -VaultName "DevTeamVault" -Force -DefaultVault
        
    .NOTES
        You must be authenticated and have the vault unlocked using Unlock-VaultwardenVault before using this function.
        In Vaultwarden/Bitwarden CLI, vaults are implemented as folders.
    #>
    
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$VaultName,
        
        [Parameter(Mandatory = $false)]
        [string]$Description,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        
        [Parameter(Mandatory = $false)]
        [switch]$DefaultVault,
        
        [Parameter(Mandatory = $false)]
        [switch]$PassThru,
        
        [Parameter(Mandatory = $false)]
        [bool]$RegisterVault = $true
    )
    
    begin
    {
        # Verify connection to Vaultwarden
        try
        {
            $status = & bw status | ConvertFrom-Json
            
            if ($status.status -ne "unlocked")
            {
                $errorMsg = "Vault is not unlocked. Please unlock the vault using Unlock-VaultwardenVault first."
                Write-VWLog -Message $errorMsg -Level Error -Category Vault -EventId 3001
                throw $errorMsg
            }
            
            Write-VWLog -Message "Connected to Vaultwarden and vault is unlocked" -Level Verbose -Category Vault
        }
        catch
        {
            $errorMsg = "Failed to connect to Vaultwarden: $_"
            Write-VWLog -Message $errorMsg -Level Error -Category Vault -EventId 3002 -Exception $_.Exception
            throw $errorMsg
        }
    }
    
    process
    {
        try
        {
            # Check if the vault (folder) already exists by looking for folders with this name
            Write-VWLog -Message "Checking if vault (folder) '$VaultName' already exists..." -Level Verbose -Category Vault
            
            # List existing folders
            $folders = & bw list folders 2>&1 | ConvertFrom-Json -ErrorAction SilentlyContinue
            
            $vaultExists = $false
            $existingFolderId = $null
            
            if ($folders -and $folders.Count -gt 0)
            {
                foreach ($folder in $folders)
                {
                    if ($folder.name -eq $VaultName)
                    {
                        $vaultExists = $true
                        $existingFolderId = $folder.id
                        break
                    }
                }
            }
            
            if ($vaultExists)
            {
                if (-not $Force)
                {
                    $msg = "Vault '$VaultName' already exists. Use -Force to recreate it."
                    Write-VWLog -Message $msg -Level Warning -Category Vault -EventId 3003
                    throw $msg
                }
                else
                {
                    # When -Force is specified and vault exists, delete the existing vault (folder) first
                    if ($PSCmdlet.ShouldProcess("Delete existing vault '$VaultName'"))
                    {
                        Write-VWLog -Message "Deleting existing vault '$VaultName' because -Force was specified" -Level Warning -Category Vault
                        
                        # Delete the folder
                        & bw delete folder $existingFolderId | Out-Null
                        
                        Write-VWLog -Message "Deleted existing vault '$VaultName'" -Level Information -Category Vault -EventId 3004
                        
                        # Reset vault existence flag since we've deleted it
                        $vaultExists = $false
                    }
                }
            }
            
            # Create the new vault (folder) if it doesn't exist (or was deleted with -Force)
            if (-not $vaultExists)
            {
                if ($PSCmdlet.ShouldProcess("Create new vault '$VaultName'"))
                {
                    Write-VWLog -Message "Creating new vault '$VaultName'" -Level Information -Category Vault
                    
                    # Prepare the JSON template for the new folder/vault
                    $vaultTemplate = @{
                        name = $VaultName
                    }
                    
                    # Note: Folders don't directly support descriptions in Bitwarden CLI
                    # If Description is provided, we'll store it as metadata later
                    
                    # Convert to JSON and create the folder
                    $vaultJson = $vaultTemplate | ConvertTo-Json -Compress
                    
                    # First encode the JSON
                    $encodedJson = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($vaultJson))
                    
                    # Execute the command and capture output properly
                    $rawOutput = & bw create folder $encodedJson 2>&1
                    
                    # Check if the output is an error message (doesn't start with '{')
                    if ($rawOutput -is [System.Management.Automation.ErrorRecord] -or 
                        ($rawOutput -is [string] -and -not ($rawOutput.Trim().StartsWith('{'))))
                    {
                        throw "Failed to create vault. Command returned: $rawOutput"
                    }
                    
                    # Now safely convert the JSON response
                    try
                    {
                        $newVault = $rawOutput | ConvertFrom-Json -ErrorAction Stop
                        
                        if (-not $newVault -or -not $newVault.id)
                        {
                            throw "Invalid vault creation response. Missing ID in response."
                        }
                    }
                    catch
                    {
                        Write-VWLog -Message "JSON conversion error: $_" -Level Error -Category Vault -EventId 3008
                        throw "Failed to process vault creation response: $_. Raw output: $rawOutput"
                    }
                    
                    Write-VWLog -Message "Successfully created vault '$VaultName' with ID: $($newVault.id)" -Level Information -Category Vault -EventId 3005
                    
                    # If Description is provided, store it as a custom field in a dummy item within the folder
                    if ($Description)
                    {
                        try
                        {
                            # Create a metadata item in the new folder
                            $metadataItem = @{
                                name       = "$VaultName - Info"
                                notes      = $Description
                                folderId   = $newVault.id
                                secureNote = @{
                                    type = 0 # SecureNote type
                                }
                                type       = 2 # SecureNote
                            }
                            
                            $metadataJson = $metadataItem | ConvertTo-Json -Compress
                            $encodedMetadata = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($metadataJson))
                            
                            # Create the metadata item
                            $metadataOutput = & bw create item $encodedMetadata 2>&1
                            Write-VWLog -Message "Added description to vault as metadata item" -Level Verbose -Category Vault
                        }
                        catch
                        {
                            Write-VWLog -Message "Failed to add description to vault. This is non-critical: $_" -Level Warning -Category Vault
                        }
                    }
                    
                    # If DefaultVault is specified, mark this vault as the default
                    if ($DefaultVault)
                    {
                        Write-VWLog -Message "Setting '$VaultName' as the default vault" -Level Information -Category Vault
                        
                        # Store this information in the module's configuration
                        $script:DefaultVaultName = $VaultName
                        
                        # Store in user preference if applicable
                        if ($script:ConfigPath -and (Test-Path -Path $script:ConfigPath))
                        {
                            $config = Get-Content -Path $script:ConfigPath | ConvertFrom-Json -ErrorAction SilentlyContinue
                            if (-not $config)
                            { 
                                $config = @{} 
                            }
                            
                            $config.DefaultVault = $VaultName
                            $config.DefaultVaultId = $newVault.id
                            
                            $config | ConvertTo-Json | Set-Content -Path $script:ConfigPath
                            
                            Write-VWLog -Message "Updated configuration file to set '$VaultName' as default vault" -Level Verbose -Category Vault
                        }
                        else
                        {
                            Write-VWLog -Message "Configuration path not found or not set. Default vault set for current session only." -Level Warning -Category Vault
                        }
                    }
                    
                    # Sync vault state after creating the new vault
                    $syncSuccess = Sync-VaultwardenState -Force
                    
                    if (-not $syncSuccess)
                    {
                        Write-VWLog -Message "Warning: Vault sync after creation may have failed" -Level Warning -Category Vault -EventId 3006
                    }
                    
                    # Register the vault with SecretManagement if specified
                    if ($RegisterVault)
                    {
                        try
                        {
                            Write-VWLog -Message "Registering vault '$VaultName' with SecretManagement" -Level Information -Category Vault
                            
                            # Get the current Vaultwarden URL from environment or use default
                            $vaultwardenUrl = $env:BW_URL
                            if (-not $vaultwardenUrl)
                            {
                                $vaultwardenUrl = (& bw config server) 2>&1
                            }
                            
                            # Register the vault with SecretManagement
                            $registerResult = Register-VaultwardenVault -VaultName $VaultName -Force
                            
                            if ($registerResult)
                            {
                                Write-VWLog -Message "Successfully registered vault '$VaultName' with SecretManagement" -Level Information -Category Vault
                            }
                            else
                            {
                                Write-VWLog -Message "Failed to register vault '$VaultName' with SecretManagement" -Level Warning -Category Vault
                            }
                        }
                        catch
                        {
                            Write-VWLog -Message "Error registering vault with SecretManagement: $_" -Level Warning -Category Vault
                            Write-Warning "Vault created successfully but registration with SecretManagement failed. Use Register-VaultwardenVault manually."
                        }
                    }
                    
                    # Return the created vault if PassThru is specified
                    if ($PassThru)
                    {
                        return $newVault
                    }
                    
                    return $true
                }
            }
        }
        catch
        {
            Write-VWLog -Message "Failed to create vault '$VaultName'" -Level Error -Category Vault -EventId 3007 -Exception $_.Exception
            throw $_
        }
    }
    
    end
    {
        # Nothing to do in the end block
    }
}