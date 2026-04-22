## Slide 1: Azure Container Apps Abuse

Module 07 — Command Execution, Secret Exfiltration, and Managed Identity Token Theft

**Speaker Notes:**
Welcome to Module 07. Container Apps are serverless containers that present a unique attack surface — RBAC permissions control who can exec into running containers, list secrets, and manipulate revisions. An attacker with the right permissions can execute commands inside containers, steal managed identity tokens, and exfiltrate secrets. Detection relies on ContainerAppConsoleLogs, ContainerAppSystemLogs, and AzureActivity.

## Slide 2: Agenda

- Module Objective and MITRE ATT&CK Mapping
- Container Apps Attack Surface and Key Permissions
- Attack Scenarios: Exec, Secret Exfil, Token Theft, Image Swap
- Enabling Diagnostic Logging
- Key Log Tables
- KQL Detection Queries
- Defender for Containers
- Incident Response (NIST Phases)
- Hardening Controls

**Speaker Notes:**
Container Apps combine serverless convenience with container flexibility — and a broad attack surface. The key permissions are listsecrets (extract app secrets), getauthtoken (get dev API tokens for exec/logs/port-forward), and write (deploy malicious revisions). We'll cover five attack scenarios, the logging tables, and detection queries that identify exec activity, image swaps, and authentication changes.

## Slide 3: Objective and MITRE Mapping

!layout: Title and Content

**Objective:** Hunt for Container App exploitation including command execution, secret exfiltration, managed identity token theft, and malicious revision deployment.

| Technique | ID | Tactic |
|---|---|---|
| Valid Accounts: Cloud Accounts | T1078.004 | Initial Access, Persistence |
| Command and Scripting Interpreter | T1059 | Execution |
| Unsecured Credentials | T1552 | Credential Access |
| Deploy Container | T1609 | Execution |
| Container Administration Command | T1610 | Execution |
| Steal Application Access Token | T1528 | Credential Access |
| Cloud Service Discovery | T1526 | Discovery |
| Exfiltration to Cloud Storage | T1567 | Exfiltration |

**Speaker Notes:**
Container Apps map to eight MITRE techniques spanning initial access through exfiltration. T1059 and T1610 cover the exec capability — running arbitrary commands inside containers. T1609 covers deploying malicious container images via revision updates. T1552 and T1528 cover secret extraction and managed identity token theft. This is one of the broadest MITRE mappings of any module.

## Slide 4: Key Permissions — Attack Surface

!layout: Title and Content

| Permission | Red Team Value |
|---|---|
| containerapps/read | Discover apps, configurations, environment |
| containerapps/write | Create or update apps — deploy malicious revisions |
| containerapps/listsecrets/action | Extract app secrets and connection strings |
| containerapps/getauthtoken/action | Get dev API tokens for exec, log stream, port forward |
| containerapps/revisions/read | Enumerate past revisions for rollback attacks |
| containerapps/authconfigs/write | Modify authentication — disable auth requirements |
| containerapps/sourcecontrols/write | Hijack CI/CD source control configuration |
| jobs/start/action | Trigger container app jobs |

**Most dangerous:** `getauthtoken` — enables exec into running containers, which enables everything else.

**Speaker Notes:**
The getauthtoken permission is the key to container exploitation. It returns a development API token that enables az containerapp exec — direct shell access into a running container. From inside the container, the attacker can access environment variables (which contain secrets), query the managed identity endpoint for tokens, and exfiltrate data. listsecrets provides a direct API path to extract secrets without exec. Write permission allows deploying a new revision with a malicious container image. Each of these permissions generates detectable events.

## Slide 5: Attack Scenarios

!layout: Title and Content

**Scenario 1 — Secret exfiltration via listsecrets:**
- `az containerapp secret list` extracts all app secrets directly via ARM API

**Scenario 2 — Managed identity token theft:**
- Exec into container, query IDENTITY_ENDPOINT for ARM/Graph/KV tokens
- Use tokens from attacker infrastructure for lateral movement

**Scenario 3 — Authentication config manipulation:**
- Modify auth config to disable authentication requirements
- Access the app without credentials

**Scenario 4 — Revision/image swap backdoor:**
- Deploy new revision with attacker-controlled container image
- Image contains backdoor, crypto miner, or exfiltration logic

**Scenario 5 — CI/CD source control hijack:**
- Modify source control configuration to point to attacker repository
- Next deployment deploys attacker code

**Speaker Notes:**
These five scenarios cover the full container attack surface. Scenario 1 is the simplest — a single API call extracts all secrets. Scenario 2 is the most impactful — managed identity tokens enable lateral movement to any resource the MI has access to. Scenario 4 is the most persistent — a malicious revision continues running until someone notices. In the lab, students will detect scenarios 1 and 2 using the KQL queries we'll cover next.

## Slide 6: Enabling Diagnostic Logging

!layout: Title and Content

**Required:** Enable diagnostic settings at the Container Apps environment level, NOT the individual app level.

**Log categories:**
- Console logs (stdout/stderr from containers)
- System logs (revision events, Dapr, traffic, auth changes)

**Key tables created:**

| Table | What It Captures |
|---|---|
| ContainerAppConsoleLogs_CL | App stdout/stderr (container output) |
| ContainerAppSystemLogs_CL | System events: revisions, auth, traffic changes |
| CloudProcessEvents | Process execution within containers (Defender XDR) |
| AzureActivity | Control plane: deployments, RBAC changes, secret operations |

**Speaker Notes:**
A critical distinction: diagnostic settings must be enabled at the Container Apps ENVIRONMENT level, not individual apps. This is a common misconfiguration — organizations enable logging per app and miss new apps created in the same environment. CloudProcessEvents from Defender for Containers provides process-level visibility inside the container — which processes are running, command-line arguments, and parent-child relationships. This is the richest signal for detecting exec-based attacks.

## Slide 7: KQL — Detect Exec and Auth Token Activity

!layout: Title and Content

```kql
ContainerAppSystemLogs_CL
| where Log_s contains "exec"
    or Log_s contains "getauthtoken"
| project Time = TimeGenerated,
          AppName = ContainerAppName_s,
          Message = Log_s
| order by TimeGenerated desc
```

**What this detects:** Command execution (exec) and development API token requests — the two highest-risk operations.

**Detect container image changes (backdoor/swap):**
```kql
ContainerAppConsoleLogs_CL
| summarize Images = make_set(ContainerImage_s)
    by ContainerAppName_s
| where array_length(Images) > 1
```

**What this detects:** Apps that have run multiple different container images — may indicate an image swap attack.

**Speaker Notes:**
The exec detection query is simple but effective — exec and getauthtoken strings in system logs are clear indicators of interactive container access. In most production environments, containers shouldn't have exec sessions. Any exec event warrants investigation. The image change query identifies apps running multiple images, which may indicate an attacker deployed a new revision with a different image. In stable environments, container images should be consistent across revisions.

## Slide 8: KQL — Detect Auth Config and Traffic Changes

!layout: Title and Content

**Authentication configuration changes:**
```kql
ContainerAppSystemLogs_CL
| where Log_s contains "Auth"
    or Log_s contains "authentication"
| project Time = TimeGenerated,
          AppName = ContainerAppName_s,
          Message = Log_s
| order by Time desc
```

**Suspicious stderr output (errors, unauthorized access):**
```kql
ContainerAppConsoleLogs_CL
| where Log_s contains "error"
    or Log_s contains "exception"
    or Log_s contains "unauthorized"
| project Time = TimeGenerated,
          AppName = ContainerAppName_s,
          Container = ContainerName_s,
          Image = ContainerImage_s,
          Message = Log_s
| order by Time desc
| take 200
```

**Speaker Notes:**
Authentication configuration changes are critical — an attacker may disable auth to access the app without credentials. Track these changes in system logs and correlate with AzureActivity for the user who made the change. The stderr query catches runtime errors that may indicate exploitation — unauthorized access attempts, exceptions from malicious code, or error messages from failed lateral movement attempts. Both queries should be part of your regular hunting cadence for Container Apps.

## Slide 9: Incident Response

!layout: Title and Content

**Phase 1 — Detection:** Check Defender XDR alerts, Advanced Hunting (CloudProcessEvents), KQL queries on console/system logs.

**Phase 2 — Containment:**
- Isolate the container app (restrict network egress)
- Deactivate the compromised revision
- Remove managed identity role assignments to block lateral movement
- Revoke getauthtoken-generated dev API tokens

**Phase 3 — Eradication:**
- Rotate all app secrets and connection strings
- Redeploy from known-good container image
- Regenerate managed identity credentials
- Review all revision history for unauthorized changes

**Phase 4 — Hardening:**
- Restrict getauthtoken/listsecrets permissions to break-glass only
- Enable Defender for Containers
- Implement network segmentation and egress controls
- Use private container registries with image signing

**Speaker Notes:**
Containment must be fast — deactivate the compromised revision immediately to stop any ongoing exfiltration. Remove managed identity role assignments to prevent the stolen tokens from being used for lateral movement. In the eradication phase, rotate everything: secrets, connection strings, and managed identity credentials. Redeploy from a known-good image — do NOT trust the current running image. For hardening, the most impactful control is restricting getauthtoken and listsecrets permissions to break-glass accounts only.

## Slide 10: Key Takeaways and References

!layout: Title and Content

- getauthtoken is the most dangerous Container App permission — it enables exec and everything that follows
- Enable diagnostic logging at the environment level, not individual app level
- Image changes across revisions indicate potential backdoor deployment
- Managed identity token theft from inside containers enables lateral movement to any accessible resource
- Restrict exec/listsecrets permissions to break-glass accounts in production

**References:**
| Resource | Link |
|---|---|
| Container Apps Security | learn.microsoft.com/azure/container-apps/security-concept |
| Container Apps Monitoring | learn.microsoft.com/azure/container-apps/observability |
| Defender for Containers | learn.microsoft.com/azure/defender-for-cloud/defender-for-containers-introduction |
| Container Apps RBAC | learn.microsoft.com/azure/container-apps/azure-resource-manager-api-spec |

**Speaker Notes:**
Module 07 is the first of two compute-platform modules. The patterns here — managed identity token theft, code execution, and secret extraction — also apply to Module 08 (Web Apps). Encourage students to audit getauthtoken permissions in their Container Apps environments. Module 08 covers Azure Web Apps, which have a similar attack surface but with different detection tables.
