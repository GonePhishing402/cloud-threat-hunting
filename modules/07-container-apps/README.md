# Module 07 — Azure Container Apps: Threat Hunting & Incident Response

## Overview

Azure Container Apps is a serverless container platform built on Kubernetes and KEDA. Because operators interact with apps via ARM/REST APIs rather than direct Kubernetes access, the attack surface is defined largely by **Azure RBAC** (who can deploy, exec, list secrets) and the **runtime environment** (what the container can do once running).

This module covers how attackers abuse Container Apps permissions and features, how defenders monitor and detect threats using Azure Monitor and Microsoft Defender for Containers, and how to execute a structured incident response.

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Valid Accounts: Cloud Accounts | T1078.004 | Abusing legitimate identities with Container Apps RBAC roles |
| Command and Scripting Interpreter | T1059 | Exec into running containers to run arbitrary commands |
| Unsecured Credentials | T1552 | Exfiltrating secrets via `listsecrets` ARM action |
| Deploy Container | T1609 | Deploying malicious containers via ARM revision updates |
| Container Administration Command | T1610 | Direct `exec` into running containers |
| Steal Application Access Token | T1528 | Stealing managed identity tokens via IMDS |
| Cloud Service Discovery | T1526 | Enumerating container apps, environments, and registries |
| Exfiltration to Cloud Storage | T1567 | Exfiltrating data to attacker-controlled storage |

---

## Key Log Tables

| Table | Destination | Description |
|---|---|---|
| `ContainerAppConsoleLogs_CL` | Log Analytics | App stdout/stderr (container output) |
| `ContainerAppSystemLogs_CL` | Log Analytics | System events: revisions, Dapr, traffic, auth changes |
| `ContainerAppConsoleLogs` | Azure Monitor | Same as above (no `_CL` suffix) |
| `ContainerAppSystemLogs` | Azure Monitor | Same as above (no `_CL` suffix) |
| `CloudProcessEvents` | Defender XDR | Process execution within containers (Advanced Hunting) |
| `CloudAuditEvents` | Defender XDR | ARM-level operations on Container Apps (Advanced Hunting) |
| `AzureActivity` | Azure Monitor | Control plane operations (deployments, role changes) |

---

## Key Attack Scenarios

1. **Secret Exfiltration via `listsecrets`** — Contributor-level identity calls `POST /listsecrets` to dump all environment variables and Key Vault references
2. **Managed Identity Token Theft** — Attacker execs into a running container and queries IMDS at `169.254.169.254` to obtain an OAuth token for downstream Azure resources
3. **Authentication Bypass via Config Manipulation** — Attacker with write access modifies built-in auth settings to disable authentication or redirect to a controlled IdP
4. **Revision/Image Swap Backdoor** — A new revision is deployed with a malicious image, traffic is gradually shifted, and the original revision is deactivated to hide the change
5. **Source Control / CI-CD Hijack** — GitHub Actions or Azure DevOps pipelines with Container Apps deploy permissions are compromised to push backdoored images

---

## Module Files

| File | Description |
|---|---|
| [Attack.md](Attack.md) | Attacker perspective: permissions, techniques, exploitation commands |
| [Defend.md](Defend.md) | Logging configuration, KQL queries, alert rules, Defender for Containers |
| [Mitigate.md](Mitigate.md) | NIST-aligned IR playbook: detection, containment, recovery, hardening |

---

## Prerequisites

- Azure subscription with Container Apps deployed
- Log Analytics workspace connected to the Container Apps Environment
- Microsoft Defender for Containers enabled
- Microsoft Sentinel (optional — for automated playbooks)
- `az` CLI and `kubectl` (for containment steps)

---

## References
- [Azure Container Apps Documentation](https://learn.microsoft.com/azure/container-apps/)
- [Log Options in Azure Container Apps](https://learn.microsoft.com/azure/container-apps/log-options)
- [Secure Your Container Apps Deployment](https://learn.microsoft.com/azure/container-apps/secure-deployment)
- [Overview of Microsoft Defender for Containers](https://learn.microsoft.com/azure/defender-for-cloud/defender-for-containers-introduction)
- [Investigate and Respond to Container Threats — XDR](https://learn.microsoft.com/defender-xdr/investigate-respond-container-threats)
- [Azure Container Apps Authentication & Authorization](https://learn.microsoft.com/azure/container-apps/authentication)
- [Managed Identities in Azure Container Apps](https://learn.microsoft.com/azure/container-apps/managed-identity)
