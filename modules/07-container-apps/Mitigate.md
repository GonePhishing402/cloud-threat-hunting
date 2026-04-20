# Mitigate: Azure Container Apps — Incident Response Playbook

This playbook follows the **NIST SP 800-61** incident response lifecycle: **Preparation → Detection & Analysis → Containment → Eradication & Recovery → Post-Incident Activity**.

---

## Phase 1 — Preparation

### Prerequisites

- **Diagnostic logging** enabled on your Container Apps Environment (sending to Log Analytics)
- **Microsoft Defender for Containers** enabled on the subscription
- **Microsoft Sentinel** connected to the same Log Analytics workspace
- **RBAC** enforced — least-privilege roles assigned; `Microsoft.App/containerApps/listsecrets/action` limited to break-glass accounts only
- Managed Identity roles reviewed monthly; unused federated credentials removed

### Runbook Access

Prepare and test the following before an incident:

| Runbook | Purpose |
|---|---|
| Disable revision | Remove malicious revision from traffic |
| Rotate secrets | Invalidate compromised secrets/tokens |
| Redeploy from known-good image | Replace compromised containers |
| Block managed identity | Remove role assignments from compromised identity |

---

## Phase 2 — Detection & Analysis

### Investigate in Microsoft Defender XDR

1. Navigate to [Microsoft Defender XDR](https://security.microsoft.com) > **Incidents & Alerts**
2. Filter by **Product name**: `Microsoft Defender for Containers`
3. Open the incident and examine the **Incident graph** for:
   - Pod / container entities
   - Service account anomalies
   - Process execution trees (look for `exec` commands, shell spawns)
   - Lateral movement paths to secrets or IMDS

### Advanced Hunting — CloudProcessEvents

```kusto
// Identify suspicious process execution within containers
CloudProcessEvents
| where TimeGenerated > ago(24h)
| where ProcessCommandLine contains "curl" or ProcessCommandLine contains "wget"
    or ProcessCommandLine contains "/bin/sh" or ProcessCommandLine contains "python"
| project TimeGenerated, PodName, PodNamespace, ContainerName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

### Advanced Hunting — CloudAuditEvents

```kusto
// Detect secret listings against Container Apps
CloudAuditEvents
| where TimeGenerated > ago(24h)
| where ActionType == "ListSecrets" or ActionType == "MicrosoftAppContainerAppsListSecrets"
| project TimeGenerated, ActionType, AccountName, ResourceId, AdditionalFields
| order by TimeGenerated desc
```

### Advanced Hunting — Managed Identity Token Requests (IMDS)

```kusto
// IMDS token requests from container workloads via Defender for Containers
CloudProcessEvents
| where ProcessCommandLine contains "169.254.169.254" or ProcessCommandLine contains "identity/oauth2/token"
| project TimeGenerated, PodName, ContainerName, ProcessCommandLine
| order by TimeGenerated desc
```

### KQL Queries — Container Apps Log Analytics

```kusto
// Auth config changes
ContainerAppSystemLogs_CL
| where Log_s contains "Auth config" or Log_s contains "authentication"
| project TimeGenerated, ContainerAppName_s, Log_s
| order by TimeGenerated desc

// Revision image changes (potential backdoor)
ContainerAppConsoleLogs_CL
| summarize Images=make_set(ContainerImage_s) by ContainerAppName_s
| where array_length(Images) > 1

// exec or token activity
ContainerAppSystemLogs_CL
| where Log_s contains "exec" or Log_s contains "getauthtoken"
| project TimeGenerated, ContainerAppName_s, RevisionName_s, Log_s
| order by TimeGenerated desc
```

---

## Phase 3 — Containment

### Option A — Isolate / Restrict / Terminate Pod (Microsoft Defender XDR)

From the **Incident graph** in the [XDR portal](https://security.microsoft.com):

1. Select the **Pod** entity on the incident graph
2. Choose one of the available response actions:

| Action | Effect | Requirements |
|---|---|---|
| **Isolate pod** | Blocks all inbound/outbound traffic; pod continues running for forensics | Network plugin: Calico/Cilium; K8s ≥ 1.27 |
| **Restrict pod** | Blocks all traffic except to kube-apiserver | Same as isolate |
| **Terminate pod** | Stops and removes the pod | No special requirements |

> **Note**: Pod isolation/restriction/termination actions are available for AKS-backed workloads. For Container Apps specifically, use revision deactivation and scaling to zero as an equivalent containment step.

### Option B — Deactivate Malicious Revision (Container Apps)

```bash
# List all revisions and their active traffic %
az containerapp revision list \
  --name <containerapp-name> \
  --resource-group <resource-group> \
  --query "[].{Name:name, Active:properties.active, Traffic:properties.trafficWeight}" \
  --output table

# Deactivate the identified malicious revision
az containerapp revision deactivate \
  --name <containerapp-name> \
  --resource-group <resource-group> \
  --revision <revision-name>

# Set traffic weight to 0 for the revision (belt-and-suspenders)
az containerapp ingress traffic set \
  --name <containerapp-name> \
  --resource-group <resource-group> \
  --revision-weight "<revision-name>=0"
```

### Option C — Remove Managed Identity Role Assignments

```bash
# List role assignments for the managed identity
az role assignment list --assignee <managed-identity-client-id> --output table

# Remove a specific role assignment
az role assignment delete \
  --assignee <managed-identity-client-id> \
  --role "<role-name>" \
  --scope <scope>
```

### Option D — Block External Egress (Network Restriction)

```bash
# Update the Container App environment to restrict egress
# (Requires environment with virtual network integration)
az containerapp env update \
  --name <environment-name> \
  --resource-group <resource-group>
# Apply NSG rules at the vNet subnet level to block outbound
```

---

## Phase 4 — Eradication & Recovery

### Rotate Compromised Secrets

```bash
# List all secrets for the container app
az containerapp secret list \
  --name <containerapp-name> \
  --resource-group <resource-group>

# Set a new secret value
az containerapp secret set \
  --name <containerapp-name> \
  --resource-group <resource-group> \
  --secrets "<secret-name>=<new-value>"

# Update the revision to use the new secret and create a new revision
az containerapp update \
  --name <containerapp-name> \
  --resource-group <resource-group>
```

### Redeploy from Known-Good Image

```bash
# Update the container app to a verified, known-good image hash
az containerapp update \
  --name <containerapp-name> \
  --resource-group <resource-group> \
  --image <registry>/<image>@sha256:<known-good-digest>

# This forces a new revision — activate it and route full traffic
az containerapp ingress traffic set \
  --name <containerapp-name> \
  --resource-group <resource-group> \
  --label-weight latest=100
```

### Multi-Region Recovery

If the primary region is compromised, fail over to a secondary deployment:

1. Ensure a secondary Container Apps Environment exists in another Azure region
2. Update your Azure Front Door or Traffic Manager profile to route to the secondary endpoint
3. Validate health of the secondary environment before completing cutover

> Reference: [Secure Deployment — Backup and Recovery](https://learn.microsoft.com/azure/container-apps/secure-deployment#backup-and-recovery)

---

## Phase 5 — Post-Incident Activity

### Hardening Checklist

| Control | Action |
|---|---|
| **Secrets** | Move all secrets to Azure Key Vault; remove secrets stored inline in Container App settings |
| **Managed Identity** | Audit all role assignments; remove unnecessary permissions |
| **Image provenance** | Enforce image digest pinning (`@sha256:...`) — prevent tag mutation attacks |
| **Authentication** | Enable Container Apps built-in auth or configure an upstream WAF/API gateway |
| **Registry** | Enable [Microsoft Defender for Container Registry](https://learn.microsoft.com/azure/defender-for-cloud/defender-for-containers-introduction) vulnerability scanning |
| **Network** | Integrate with a virtual network; restrict ingress to known IP ranges |
| **Logging** | Verify diagnostic settings are active; test KQL alert rules are firing |
| **Revision management** | Disable auto-deployment from unrestricted CI/CD pipelines; require signed commits |
| **RBAC** | Remove `Microsoft.App/containerApps/listsecrets/action` from non-admin identities |

### Lessons-Learned Document

Capture the following within 72 hours:
1. Timeline of events (first indicator → containment → recovery)
2. MITRE ATT&CK techniques observed
3. Gaps in logging or detection (what was missed and why)
4. Changes made to hardening controls
5. Updated runbooks

---

## Microsoft Learn References
- [Investigate and Respond to Container Threats — Microsoft Defender XDR](https://learn.microsoft.com/defender-xdr/investigate-respond-container-threats)
- [Secure Your Container Apps Deployment](https://learn.microsoft.com/azure/container-apps/secure-deployment)
- [Backup and Recovery for Container Apps](https://learn.microsoft.com/azure/container-apps/secure-deployment#backup-and-recovery)
- [Overview of Microsoft Defender for Containers](https://learn.microsoft.com/azure/defender-for-cloud/defender-for-containers-introduction)
- [Alerts for Kubernetes Clusters](https://learn.microsoft.com/azure/defender-for-cloud/alerts-containers)
- [Azure Container Apps Revisions](https://learn.microsoft.com/azure/container-apps/revisions)
- [Managed Identities in Azure Container Apps](https://learn.microsoft.com/azure/container-apps/managed-identity)
- [Azure Container Apps — Managed Secrets](https://learn.microsoft.com/azure/container-apps/manage-secrets)
- [NIST SP 800-61 Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
