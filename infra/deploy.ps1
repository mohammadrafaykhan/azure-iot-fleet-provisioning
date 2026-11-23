<#
.SYNOPSIS
    Deploy IoT Hub, DPS, the managed-identity link, the fleet root CA, and operator RBAC.
.DESCRIPTION
    Requires the PKI first (python -m pki root; python -m pki intermediate devices).
    Uses the signed-in Azure CLI identity as the operator. Writes .env from the
    deployment outputs when .env does not exist yet; otherwise prints the values.
.EXAMPLE
    ./infra/deploy.ps1 -ResourceGroup rg-iot-fleet-dev -Location centralindia
#>
[CmdletBinding()]
param(
    [string]$ResourceGroup = 'rg-iot-fleet-dev',
    [string]$Location = 'centralindia'
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent

function Invoke-Az {
    $output = & az @args
    if ($LASTEXITCODE -ne 0) { throw "az $($args -join ' ') failed (exit $LASTEXITCODE)" }
    return $output
}

$rootCert = Join-Path $repo 'certs/root-ca.cert.pem'
if (-not (Test-Path $rootCert)) {
    throw "Root CA not found at $rootCert. Run 'python -m pki root' and 'python -m pki intermediate devices' first."
}
$python = Join-Path $repo '.venv/Scripts/python.exe'
if (-not (Test-Path $python)) { $python = 'python' }
$rootCaDer = & $python -m pki der $rootCert
if ($LASTEXITCODE -ne 0) { throw 'Could not read the root CA certificate.' }

$operatorId = Invoke-Az ad signed-in-user show --query id -o tsv
Write-Host "Operator object id: $operatorId"

Invoke-Az group create --name $ResourceGroup --location $Location `
    --tags project=azure-iot-fleet-provisioning environment=dev -o none
Write-Host "Resource group $ResourceGroup ready in $Location"

$deploymentName = "fleet-$(Get-Date -Format 'yyyyMMddHHmmss')"
$outputs = Invoke-Az deployment group create --resource-group $ResourceGroup --name $deploymentName `
    --template-file (Join-Path $PSScriptRoot 'main.bicep') `
    --parameters operatorPrincipalId=$operatorId rootCaCertificate=$rootCaDer `
    --query properties.outputs -o json | ConvertFrom-Json

$values = [ordered]@{
    DPS_ID_SCOPE         = $outputs.dpsIdScope.value
    DPS_HOST             = $outputs.dpsDeviceHostName.value
    CERTS_DIR            = 'certs'
    STATE_DIR            = 'state'
    DPS_SERVICE_HOSTNAME = $outputs.dpsServiceHostName.value
    IOTHUB_HOSTNAME      = $outputs.iotHubHostName.value
}

$envFile = Join-Path $repo '.env'
if (Test-Path $envFile) {
    Write-Host "`n.env already exists; update it with:" -ForegroundColor Yellow
    $values.GetEnumerator() | ForEach-Object { Write-Host "$($_.Key)=$($_.Value)" }
} else {
    $values.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" } |
        Set-Content -Path $envFile -Encoding ascii
    Write-Host "`nWrote $envFile" -ForegroundColor Green
}

Write-Host "`nDeployed DPS $($outputs.dpsName.value). Role assignments can take 1-5 minutes before fleetctl works." -ForegroundColor Green
