// Zero-touch fleet provisioning: IoT Hub (X.509 devices only) and DPS (Entra ID only for
// service APIs), linked by DPS's managed identity, both trusting the fleet root CA.

@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('IoT Hub name (globally unique).')
param hubName string = 'iot-fleet-${uniqueString(resourceGroup().id)}'

@description('Device Provisioning Service name (globally unique).')
param dpsName string = 'dps-fleet-${uniqueString(resourceGroup().id)}'

@description('IoT Hub SKU. F1 is free (one per subscription, 8,000 messages/day).')
@allowed(['F1', 'B1', 'S1'])
param hubSku string = 'F1'

@description('Object ID of the operator who runs fleetctl.')
param operatorPrincipalId string

@allowed(['User', 'Group', 'ServicePrincipal'])
param operatorPrincipalType string = 'User'

@description('Fleet root CA certificate as base64 DER (python -m pki der certs/root-ca.cert.pem).')
param rootCaCertificate string

param rootCaName string = 'fleet-root-ca'

@description('Disable DPS shared access policies so service APIs accept Microsoft Entra ID only.')
param dpsDisableLocalAuth bool = true

param tags object = {
  project: 'azure-iot-fleet-provisioning'
  environment: 'dev'
}

var roles = {
  iotHubDataContributor: '4fc6c259-987e-4a07-842e-c321cc9d413f'
  dpsDataContributor: 'dfce44e4-17b7-4bd1-a6d1-04996ec95633'
}

var dpsProperties = {
  allocationPolicy: 'Hashed'
  disableLocalAuth: dpsDisableLocalAuth
  publicNetworkAccess: 'Enabled'
}

resource hub 'Microsoft.Devices/IotHubs@2023-06-30' = {
  name: hubName
  location: location
  tags: tags
  sku: {
    name: hubSku
    capacity: 1
  }
  properties: {
    disableDeviceSAS: true
    disableModuleSAS: true
    eventHubEndpoints: {
      events: {
        retentionTimeInDays: 1
        partitionCount: 2
      }
    }
  }
}

resource hubRootCa 'Microsoft.Devices/IotHubs/certificates@2023-06-30' = {
  parent: hub
  name: rootCaName
  properties: {
    certificate: rootCaCertificate
    isVerified: true
  }
}

resource dps 'Microsoft.Devices/provisioningServices@2026-11-01' = {
  name: dpsName
  location: location
  tags: tags
  sku: {
    name: 'S1'
    capacity: 1
  }
  identity: {
    type: 'SystemAssigned'
  }
  properties: dpsProperties
}

resource dpsRootCa 'Microsoft.Devices/provisioningServices/certificates@2026-11-01' = {
  parent: dps
  name: rootCaName
  properties: {
    certificate: rootCaCertificate
    isVerified: true
  }
}

resource dpsToHub 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(hub.id, dps.id, roles.iotHubDataContributor)
  scope: hub
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.iotHubDataContributor)
    principalId: dps.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource operatorHub 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(hub.id, operatorPrincipalId, roles.iotHubDataContributor)
  scope: hub
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.iotHubDataContributor)
    principalId: operatorPrincipalId
    principalType: operatorPrincipalType
  }
}

resource operatorDps 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(dps.id, operatorPrincipalId, roles.dpsDataContributor)
  scope: dps
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.dpsDataContributor)
    principalId: operatorPrincipalId
    principalType: operatorPrincipalType
  }
}

// The link needs DPS's identity, which exists only after DPS is created, so it is applied
// as a second update of the same resource once the identity holds its role on the hub.
module link 'dps-link.bicep' = {
  name: 'dps-link'
  params: {
    dpsName: dps.name
    location: location
    tags: tags
    properties: dpsProperties
    hubHostName: hub.properties.hostName
  }
  dependsOn: [
    dpsToHub
    dpsRootCa
  ]
}

output iotHubHostName string = hub.properties.hostName
output dpsName string = dps.name
output dpsIdScope string = dps.properties.idScope
output dpsServiceHostName string = dps.properties.serviceOperationsHostName
output dpsDeviceHostName string = dps.properties.deviceProvisioningHostName
