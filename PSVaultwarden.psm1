#requires -Version 5.1
#requires -Modules @{ ModuleName="Microsoft.PowerShell.SecretManagement"; ModuleVersion="1.1.2" }

# Script variables
$script:ModuleRoot = $PSScriptRoot
$script:FunctionsPath = Join-Path -Path $ModuleRoot -ChildPath "functions"
$script:InternalFunctionsPath = Join-Path -Path $ModuleRoot -ChildPath "internal\functions"
$script:DefaultVaultName = "VaultwardenVault"

# Import all internal functions
Get-ChildItem -Path $script:InternalFunctionsPath -Filter "*.ps1" -Recurse | ForEach-Object {
    . $_.FullName
    Write-Verbose "Imported internal function: $($_.BaseName)"
}

# Import all public functions
Get-ChildItem -Path $script:FunctionsPath -Filter "*.ps1" -Recurse | ForEach-Object {
    . $_.FullName
    Write-Verbose "Imported function: $($_.BaseName)"
}

# Cleanup on module removal
$ExecutionContext.SessionState.Module.OnRemove = {
    # Clear sensitive environment variables when module is removed
    if ($env:BW_CLIENTSECRET) { Remove-Item -Path env:BW_CLIENTSECRET -ErrorAction SilentlyContinue }
    if ($env:BW_CLIENTID) { Remove-Item -Path env:BW_CLIENTID -ErrorAction SilentlyContinue }
    Write-Verbose "Cleaned up PSVaultwarden environment variables"
}

# Module initialization code
Write-Verbose "PSVaultwarden module loaded"
