@description('Name of the Log Analytics workspace for Sentinel')
param workspaceName string

@description('Azure region for all resources')
param location string = resourceGroup().location

@description('Sentinel pricing tier')
@allowed(['PerGB2018', 'CapacityReservation'])
param sku string = 'PerGB2018'

@description('Data retention in days')
@minValue(30)
@maxValue(730)
param retentionInDays int = 90

@description('Capacity reservation in GB/day (only used when sku is CapacityReservation)')
param capacityReservationLevel int = 100

// Log Analytics Workspace
resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: workspaceName
  location: location
  properties: {
    sku: {
      name: sku
      capacityReservationLevel: sku == 'CapacityReservation' ? capacityReservationLevel : null
    }
    retentionInDays: retentionInDays
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

// Microsoft Sentinel Solution
resource sentinel 'Microsoft.SecurityInsights/onboardingStates@2022-12-01-preview' = {
  name: 'default'
  scope: workspace
  properties: {}
}

// Azure Activity Log Connector (Data Connector)
resource activityConnector 'Microsoft.SecurityInsights/dataConnectors@2022-12-01-preview' = {
  name: 'azureActivityConnector'
  scope: workspace
  kind: 'AzureActivity'
  properties: {
    linkedResourceId: subscription().id
  }
  dependsOn: [sentinel]
}

// Key Vault for lab secrets
resource keyVault 'Microsoft.KeyVault/vaults@2023-02-01' = {
  name: '${workspaceName}-kv'
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enableSoftDelete: true
    enablePurgeProtection: true
    softDeleteRetentionInDays: 90
  }
}

// Key Vault Diagnostic Settings
resource kvDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'kv-to-sentinel'
  scope: keyVault
  properties: {
    workspaceId: workspace.id
    logs: [
      {
        category: 'AuditEvent'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}

// Storage Account for lab data
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: replace('${workspaceName}stor', '-', '')
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
  }
}

// Storage Blob Service
resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {
  parent: storageAccount
  name: 'default'
}

// Storage Diagnostic Settings
resource storageDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'storage-to-sentinel'
  scope: blobService
  properties: {
    workspaceId: workspace.id
    logs: [
      { category: 'StorageRead', enabled: true }
      { category: 'StorageWrite', enabled: true }
      { category: 'StorageDelete', enabled: true }
    ]
    metrics: [
      { category: 'Transaction', enabled: true }
    ]
  }
}

// Logic App for lab scenarios
resource logicApp 'Microsoft.Logic/workflows@2019-05-01' = {
  name: '${workspaceName}-lab-logicapp'
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    state: 'Disabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      triggers: {
        manual: {
          type: 'Request'
          kind: 'Http'
          inputs: {
            schema: {}
          }
        }
      }
      actions: {}
    }
  }
}

// Logic App Diagnostic Settings
resource logicDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'logic-to-sentinel'
  scope: logicApp
  properties: {
    workspaceId: workspace.id
    logs: [
      {
        category: 'WorkflowRuntime'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}

// Outputs
output workspaceId string = workspace.id
output workspaceName string = workspace.name
output keyVaultName string = keyVault.name
output keyVaultUri string = keyVault.properties.vaultUri
output storageAccountName string = storageAccount.name
output logicAppName string = logicApp.name
