@description('Environment name (dev, prod)')
param environment string = 'prod'

@description('Azure region for resources')
param location string = 'australiaeast'

// Example storage account for testing drift detection
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'st${uniqueString(resourceGroup().id)}${environment}'
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    accessTier: 'Hot'
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
  }
}

// App Service Plan for testing SKU/capacity drift detection
resource appServicePlan 'Microsoft.Web/serverfarms@2023-01-01' = {
  name: 'asp-test-drift'
  location: location
  kind: 'linux'
  sku: {
    name: 'P3v3'
    tier: 'PremiumV3'
    family: 'Pv3'
    size: 'P3v3'
    capacity: 1
  }
  properties: {
    reserved: true
  }
}

output storageAccountId string = storageAccount.id
output storageAccountName string = storageAccount.name
output appServicePlanId string = appServicePlan.id
