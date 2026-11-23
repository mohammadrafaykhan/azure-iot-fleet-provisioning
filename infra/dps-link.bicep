// Links the IoT hub to DPS using DPS's system-assigned managed identity (no connection string).

param dpsName string
param location string
param tags object
param properties object
param hubHostName string

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
  properties: union(properties, {
    iotHubs: [
      {
        hostName: hubHostName
        location: location
        authenticationType: 'SystemAssigned'
        allocationWeight: 1
        applyAllocationPolicy: true
      }
    ]
  })
}
