<#
.SYNOPSIS
    Delete every Azure resource for azure-iot-fleet-provisioning.
.DESCRIPTION
    Removes the resource group (IoT Hub, DPS, role assignments) and clears the cached
    assignments in ./state, which point at the deleted hub. Local certificates are kept.
.EXAMPLE
    ./infra/teardown.ps1 -ResourceGroup rg-iot-fleet-dev
#>
[CmdletBinding()]
param(
    [string]$ResourceGroup = 'rg-iot-fleet-dev',
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

if ((az group exists --name $ResourceGroup) -ne 'true') {
    Write-Host "Resource group $ResourceGroup does not exist; nothing to delete."
    return
}

if (-not $Force) {
    $answer = Read-Host "Delete resource group '$ResourceGroup' and everything in it? Type the name to confirm"
    if ($answer -ne $ResourceGroup) {
        Write-Host 'Cancelled.'
        return
    }
}

az group delete --name $ResourceGroup --yes
if ($LASTEXITCODE -ne 0) { throw "Failed to delete $ResourceGroup" }
Write-Host "Deleted $ResourceGroup"

$state = Join-Path (Split-Path $PSScriptRoot -Parent) 'state'
if (Test-Path $state) {
    Remove-Item -Recurse -Force $state
    Write-Host 'Cleared cached device assignments (state/)'
}
