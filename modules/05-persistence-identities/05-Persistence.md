## Slide 1: Persistence via Managed Identities and Service Principals

Module 05 — Service Principal Backdoors, Federated Credentials, and Managed Identity Abuse

**Speaker Notes:**
Welcome to Module 05. This module covers how attackers establish persistent access in Azure by manipulating service principals, federated identity credentials, and managed identities. These persistence mechanisms survive password resets, MFA changes, and session revocations. The detection surface spans AuditLogs for identity operations and AADServicePrincipalSignInLogs for service principal authentication events.

## Slide 2: Agenda

- Module Objective and MITRE ATT&CK Mapping
- Three Persistence Techniques Overview
- Technique 1: Service Principal Credential Backdoor
- Technique 2: Backdoor SP Creation
- Technique 3: Managed Identity Token Theft
- Detection: AADServicePrincipalSignInLogs Key Fields
- KQL Detection Queries
- Detection Coverage Map
- Incident Response
- Hardening Controls

**Speaker Notes:**
This module follows three attack techniques that represent the most common persistence mechanisms in Azure. Service principal credential addition lets attackers add secrets or certificates to existing apps. Backdoor SP creation creates an entirely new service principal disguised as a legitimate app. Managed identity token theft exploits the IDENTITY_ENDPOINT on compromised resources. Each technique has specific detection patterns in AuditLogs and AADServicePrincipalSignInLogs.

## Slide 3: Objective and MITRE Mapping

!layout: Title and Content

**Objective:** Hunt for attacker persistence via service principal credentials, federated identity credentials, and managed identity abuse. Detect unauthorized credential additions, first-time SP sign-ins, and managed identity token theft.

| Technique | ID | Tactic |
|---|---|---|
| Additional Cloud Credentials | T1098.001 | Persistence |
| Create Account: Cloud Account | T1136.003 | Persistence |
| Valid Accounts: Cloud Accounts | T1078.004 | Defense Evasion, Persistence |
| Trusted Relationship | T1199 | Initial Access |

**Speaker Notes:**
T1098.001 is the core technique — adding additional credentials (secrets or certificates) to an existing service principal. T1136.003 covers creating an entirely new SP. T1078.004 covers the attacker authenticating as the backdoored SP. T1199 covers federated identity credentials, where an external identity provider is trusted to authenticate as the SP — this is the most sophisticated persistence mechanism.

## Slide 4: Three Persistence Techniques

!layout: Title and Content

| Technique | What Attacker Does | Survives Password Reset? | Detection Table |
|---|---|---|---|
| SP Credential Addition | Adds client secret or certificate to existing app | Yes — SP credentials are independent of user passwords | AuditLogs |
| Backdoor SP Creation | Creates new app registration disguised as legitimate | Yes — entirely separate identity | AuditLogs |
| Managed Identity Token Theft | Queries IDENTITY_ENDPOINT on compromised resource | N/A — uses resource's built-in identity | AADManagedIdentitySignInLogs |

**Key insight:** Service principal credentials (secrets and certificates) are independent of user accounts. Resetting a user's password or revoking their sessions does NOT affect SP credentials the attacker has added.

**Speaker Notes:**
This comparison highlights why identity persistence is so dangerous. A user's password reset doesn't affect any service principal credentials. An attacker who adds a client secret to an app registration has persistent access that's completely independent of the compromised user. Federated identity credentials are even harder to detect — they allow external identity providers to authenticate as the SP, leaving no credential artifact to find. Managed identity token theft exploits the local HTTP endpoint available on Azure resources to get tokens without any credential material.

## Slide 5: Technique 1 — SP Credential Backdoor

!layout: Title and Content

**Attack flow for PFX Certificate Discovery:**
- Attacker finds a .pfx certificate file on a compromised host
- Extracts the certificate thumbprint
- Uses the certificate to authenticate as the associated service principal
- Enumerates the SP's permissions — may have Contributor, Key Vault access, etc.

**Attack flow for Client Secret Addition:**
- Attacker with Application Administrator or app Owner role
- Adds a new client secret to an existing app registration
- Authenticates as the SP: `Connect-AzAccount -ServicePrincipal -CertificateThumbprint` or `-Credential`
- Maintains access indefinitely until the secret is removed

**Detection signal:** AuditLogs where OperationName == "Add service principal credentials" or "Update application - Certificates and secrets management"

**Speaker Notes:**
PFX certificates are commonly stored on deployment servers, CI/CD agents, or in user profile directories. An attacker who finds a .pfx file can immediately authenticate as whatever service principal it belongs to. The client secret addition path is more common — an attacker with sufficient Entra ID permissions adds a new secret to an existing high-privilege app. The secret can be set to expire in years, providing long-term persistence. Both attacks generate events in AuditLogs that we can detect.

## Slide 6: Technique 2 — Creating Backdoor Service Principals

!layout: Title and Content

**Attack flow:**
- Attacker creates a new app registration with a disguised name (e.g., "Azure Monitoring Agent")
- Creates a service principal for the app
- Adds a client secret or certificate
- Assigns RBAC roles: Contributor on target subscription, Key Vault Secrets User, etc.
- Authenticates with the new SP from attacker infrastructure

**Why it's effective:**
- New SP blends in with legitimate automation identities
- Disguised names make visual review ineffective
- SP has its own independent credential lifecycle
- RBAC assignment grants access to Azure resources

**Detection signal:** AuditLogs where OperationName == "Add application" or "Add service principal", followed by credential addition and role assignment.

**Speaker Notes:**
This is the most complete persistence mechanism — the attacker creates an entirely new identity in your tenant. They'll give it a name that looks legitimate: "Azure Monitoring Agent", "Backup Service Account", or something that blends in. Then they add credentials and assign RBAC roles. The sequence of events in AuditLogs tells the story: app creation, SP creation, credential addition, role assignment. If all four happen from the same actor within a short window, it's almost certainly an attacker establishing persistence. In the lab, you'll trace this exact pattern.

## Slide 7: Technique 3 — Managed Identity Token Theft

!layout: Title and Content

**How managed identity tokens work:**
- Azure resources with managed identities have a local HTTP endpoint: IDENTITY_ENDPOINT
- Authenticated by the IDENTITY_HEADER environment variable
- Returns access tokens for any Azure resource the MI has permissions for

**Attack flow:**
- Attacker gains code execution on an Azure resource (VM, App Service, Container App, Logic App)
- Queries the IDENTITY_ENDPOINT for tokens targeting ARM, Graph, Key Vault, Storage
- Uses tokens from attacker infrastructure for lateral movement

**Token request example:**
- `curl "${IDENTITY_ENDPOINT}?resource=https://management.azure.com/&api-version=2019-08-01" -H "X-IDENTITY-HEADER: ${IDENTITY_HEADER}"`

**Speaker Notes:**
Managed identity token theft requires code execution on the Azure resource — which we covered in Modules 03 (Logic Apps), 07 (Container Apps), and 08 (Web Apps). The IDENTITY_ENDPOINT is an HTTP endpoint that returns tokens without any credential material. The attacker just needs to know the resource URL they want to target. They can request tokens for ARM, Graph, Key Vault, Storage — whatever the managed identity has permissions for. Detection relies on AADManagedIdentitySignInLogs showing sign-ins from unexpected IPs or targeting unexpected resources.

## Slide 8: Detection — AADServicePrincipalSignInLogs Key Fields

!layout: Title and Content

| Field | Why It Matters |
|---|---|
| ServicePrincipalName | Name of the SP — check for recently created or unfamiliar names |
| ServicePrincipalId | Object ID — correlate with AuditLogs for creation events |
| ClientCredentialType | "Certificate" or "Secret" — shows which credential type was used |
| ServicePrincipalCredentialThumbprint | Certificate thumbprint — matches PFX files found on hosts |
| FederatedCredentialId | Present if federated identity credential was used |
| IPAddress | Source IP — unexpected IPs indicate attacker-controlled infrastructure |
| ResourceDisplayName | Target resource — rapid changes indicate reconnaissance |
| ResultType | 0 = success, other = failure |

**Speaker Notes:**
AADServicePrincipalSignInLogs is the primary table for detecting backdoor SP usage. ClientCredentialType tells you whether a certificate or secret was used. ServicePrincipalCredentialThumbprint is critical — if you find a .pfx file during forensics, you can search for this thumbprint to find all sign-ins using that certificate. FederatedCredentialId identifies federated identity credential usage. IPAddress is the attacker's infrastructure. Correlate the ServicePrincipalId with AuditLogs to find when the SP was created and by whom.

## Slide 9: KQL — Detect New SP Credentials

!layout: Title and Content

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any (
    "Add service principal credentials",
    "Update application"
  )
| extend Actor = tostring(
    InitiatedBy.user.userPrincipalName)
| extend SPName = tostring(
    TargetResources[0].displayName)
| extend SPId = tostring(
    TargetResources[0].id)
| project TimeGenerated, Actor, SPName, SPId,
          CorrelationId
| order by TimeGenerated desc
```

**What to investigate:** Who added credentials? To which SP? Is this part of a known deployment process?

**Speaker Notes:**
This query catches credential additions to service principals. The Actor field shows who performed the action — if it's a user account rather than a CI/CD pipeline, investigate immediately. The SPName shows which service principal received the new credential. Correlate the SPId with AADServicePrincipalSignInLogs to see if the new credential has been used for sign-ins. This is one of the highest-value persistence detection queries because credential addition is a required step in every SP backdoor attack.

## Slide 10: KQL — Detect New App Registrations and SP Creation

!layout: Title and Content

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in (
    "Add application",
    "Add service principal"
  )
| extend Actor = tostring(
    InitiatedBy.user.userPrincipalName)
| extend AppName = tostring(
    TargetResources[0].displayName)
| extend AppId = tostring(
    TargetResources[0].id)
| project TimeGenerated, Actor, OperationName,
          AppName, AppId, CorrelationId
| order by TimeGenerated desc
```

**Correlate with first sign-in:**
```kql
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| summarize FirstSignIn = min(TimeGenerated)
    by ServicePrincipalName, ServicePrincipalId,
    IPAddress
| order by FirstSignIn desc
```

**Speaker Notes:**
The first query catches new app registrations and service principal creations. The second query shows the first successful sign-in for each SP. Correlate these to find newly created SPs that have already been used for authentication. If a new SP was created by a user account and then signed in from a different IP, that's a strong indicator of a backdoor. The CorrelationId in AuditLogs can link the creation event to subsequent credential additions in the same session.

## Slide 11: KQL — Detect Certificate-Based SP Sign-Ins

!layout: Title and Content

```kql
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| where ClientCredentialType == "Certificate"
| project TimeGenerated, ServicePrincipalName,
          ServicePrincipalId, IPAddress,
          ServicePrincipalCredentialThumbprint,
          ResourceDisplayName
| order by TimeGenerated desc
```

**Why certificate-based sign-ins matter:**
- PFX certificates found on compromised hosts are used for SP authentication
- The thumbprint field connects the certificate to the sign-in event
- Unexpected IPs using certificate authentication are high-priority alerts

**Speaker Notes:**
Certificate-based SP sign-ins are legitimate for automation, but they're also the primary mechanism for PFX-based attacks. This query shows all certificate-authenticated SP sign-ins with their thumbprints and source IPs. Compare the ServicePrincipalCredentialThumbprint with any certificates found during forensics. Look for sign-ins from IPs outside your corporate or CI/CD infrastructure. In the lab, students will trace a PFX certificate from discovery on a compromised host to the corresponding sign-in events.

## Slide 12: Detection Coverage Map

!layout: Title and Content

| Attack Phase | Detection Query | Table |
|---|---|---|
| New app registration | OperationName == "Add application" | AuditLogs |
| New service principal | OperationName == "Add service principal" | AuditLogs |
| Credential addition (secret/cert) | OperationName has "credentials" | AuditLogs |
| Federated identity credential | OperationName has "federated" | AuditLogs |
| RBAC role assignment | OperationNameValue has "roleAssignments/write" | AzureActivity |
| First SP sign-in | ResultType == 0, new IP | AADServicePrincipalSignInLogs |
| MI sign-in from unexpected IP | IPAddress not in expected range | AADManagedIdentitySignInLogs |

**Speaker Notes:**
This coverage map shows how each attack phase maps to a specific detection query and table. The complete attack chain generates events across three tables: AuditLogs for identity operations, AzureActivity for RBAC changes, and AADServicePrincipalSignInLogs for authentication. An analytics rule that correlates new credential addition in AuditLogs with first sign-in in AADServicePrincipalSignInLogs within a 24-hour window is a high-fidelity detection for SP backdoors.

## Slide 13: Incident Response

!layout: Title and Content

**Immediate containment:**
- Remove unauthorized secrets and certificates from the compromised SP
- Disable the compromised SP: Enterprise Applications > Properties > Enabled for sign-in: No
- Rotate surviving credentials on legitimate SPs that share the same resource access
- Revoke excessive app role assignments

**Investigation:**
- Identify all resources accessed by the compromised SP
- Check AADServicePrincipalSignInLogs for all IPs and resources
- Trace the creation event in AuditLogs to identify the initial actor
- Check for additional persistence mechanisms (federated credentials, additional SPs)

**Recovery:**
- Re-create legitimate SPs with new credentials if the originals were compromised
- Audit all app registrations for unexpected credentials or federated identity configurations

**Speaker Notes:**
Do NOT delete the compromised SP — disable it first so you can investigate its activity. Deleting removes the audit trail. Remove the attacker's credential (secret or certificate) specifically, leaving legitimate credentials intact if the SP serves a real purpose. Check for federated identity credentials — these are harder to spot and allow external identity providers to authenticate as the SP. After containment, audit all app registrations tenant-wide for unexpected credentials.

## Slide 14: Hardening Controls

!layout: Title and Content

| Control | What It Prevents |
|---|---|
| Restrict app registration creation | Prevents users from creating new app registrations (Entra ID Settings) |
| Require admin consent for credential changes | Prevents unauthorized secret/cert additions |
| Monitor AuditLogs for credential operations | Detects backdoor attempts in near-real-time |
| Use managed identities over service principals | Eliminates credential management entirely |
| Certificate credential rotation automation | Limits exposure window for compromised certificates |
| App governance policies | Automated monitoring of app permissions and activity |
| Conditional Access for workload identities | Restricts SP sign-ins by IP, risk level |

**Speaker Notes:**
The most impactful control is restricting app registration creation to administrators only. By default, all users can create app registrations — this is the most common misconfiguration. Use Entra ID Settings to disable "Users can register applications". For legitimate automation, prefer managed identities over service principals — they eliminate credential management entirely. Conditional Access for workload identities is a newer capability that lets you apply IP restrictions and risk-based controls to SP sign-ins.

## Slide 15: Key Takeaways and References

!layout: Title and Content

- SP credentials are independent of user passwords — credential backdoors survive password resets
- Three tables cover the full detection surface: AuditLogs, AADServicePrincipalSignInLogs, AzureActivity
- Correlate credential creation in AuditLogs with first sign-in in SP logs for high-fidelity detection
- Disable compromised SPs (don't delete) to preserve investigation evidence
- Restrict app registration creation and use managed identities where possible

**References:**
| Resource | Link |
|---|---|
| App Consent Investigation Playbook | learn.microsoft.com/security/operations/incident-response-playbook-app-consent |
| Conditional Access for Workload Identities | learn.microsoft.com/entra/identity/conditional-access/workload-identity |
| AADServicePrincipalSignInLogs Schema | learn.microsoft.com/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs |
| Securing Service Principals | learn.microsoft.com/entra/identity/enterprise-apps/service-principal-best-practices |

**Speaker Notes:**
Module 05 establishes the persistence detection skills needed for the remaining modules. Service principal and managed identity abuse appear in Modules 06 (Key Vault), 07 (Container Apps), and 08 (Web Apps) as lateral movement mechanisms. Encourage students to audit their app registrations and review credential expiration dates. Module 06 moves to Key Vault — where stolen identities are used to extract secrets.
