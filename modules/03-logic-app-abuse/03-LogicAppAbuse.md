## Slide 1: Logic App Abuse in Azure

Module 03 — Data Exfiltration, Privilege Escalation, and Persistence via Logic Apps

**Speaker Notes:**
Welcome to Module 03. We shift from identity-layer attacks to Azure resource-layer attacks. Logic Apps are serverless automation workflows that attackers abuse for data exfiltration, privilege escalation through managed identities, and persistence via timer triggers. The detection surface is primarily AzureActivity — the Azure control plane log. This module teaches you to detect when someone modifies a workflow definition, harvests a trigger URL, or escalates privileges through managed identity manipulation.

## Slide 2: Agenda

- Module Objective and MITRE ATT&CK Mapping
- Why Logic Apps Are an Attack Target
- Attack Vector 1: RBAC Abuse to Edit Workflow Definitions
- Attack Vector 2: Trigger URL Harvesting (SAS Callback)
- Attack Vector 3: Managed Identity Abuse
- Detection: AzureActivity Key Fields and Operations
- KQL Detection Queries
- Investigation Workflow
- Incident Response Steps
- Hardening Controls

**Speaker Notes:**
This module covers three attack vectors that chain together: an attacker with Contributor access edits a Logic App to inject exfiltration actions, harvests the trigger URL for credential-free invocation, and abuses the Logic App's managed identity to access sensitive resources. We'll walk through each attack, then cover the AzureActivity-based detection queries, and finish with incident response and hardening. The hardening section includes Key Vault secret management and secure inputs/outputs — practical controls students can implement immediately.

## Slide 3: Objective and MITRE Mapping

!layout: Title and Content

**Objective:** Hunt for malicious use of Azure Logic Apps including data exfiltration via connectors, privilege escalation through managed identities, and persistence via timer triggers.

| Technique | ID | Tactic |
|---|---|---|
| Serverless Execution | T1648 | Execution |
| Automated Exfiltration | T1020 | Exfiltration |
| Abuse Elevation Control Mechanism | T1548 | Privilege Escalation |
| Scheduled Task/Job | T1053 | Persistence |
| Exfiltration Over Web Service | T1567 | Exfiltration |
| Account Manipulation | T1098 | Persistence |

**Speaker Notes:**
Logic App abuse maps to six MITRE techniques across four tactics: execution, exfiltration, privilege escalation, and persistence. T1648 (Serverless Execution) is the core — Logic Apps execute code without the attacker needing to maintain infrastructure. T1020 and T1567 cover the exfiltration via HTTP connectors. T1548 covers the managed identity abuse for privilege escalation. T1053 covers timer-triggered persistence. T1098 covers RBAC manipulation for long-term access.

## Slide 4: Why Logic Apps Are an Attack Target

!layout: Title and Content

**Logic App characteristics that attackers exploit:**
- Workflow definitions are JSON — anyone with Contributor can edit them via portal, CLI, or REST API
- No change-approval gate by default — a workflows/write operation takes effect immediately
- Managed identities provide credential-free access to Azure resources
- Trigger URLs use SAS tokens — anyone with the URL can invoke the workflow without Azure auth
- Timer triggers provide persistence that survives attacker credential revocation
- Run history exposes inputs and outputs of every action (unless secured)

| Role | Can Edit Workflows? | Notes |
|---|---|---|
| Owner | Yes | Full control |
| Contributor | Yes | Most common misconfiguration |
| Logic App Contributor | Yes | Scoped to Logic Apps only |
| Logic App Operator | No | Can only enable/disable |

**Speaker Notes:**
The key insight is that Logic Apps combine code execution, credential access, and external connectivity in a single resource that's often under-monitored. Contributor is the most common misconfiguration — it grants workflow write permissions alongside everything else. An attacker who compromises a Contributor account can immediately edit any Logic App in the resource group. The JSON definition is the attack surface — injecting an HTTP action takes seconds. Logic App Operator is the safe role for operations teams who just need to enable/disable workflows.

## Slide 5: Attack Vector 1 — RBAC Abuse to Edit Workflows

!layout: Title and Content

**Attack flow:**
- Attacker with Contributor access enumerates Logic Apps: `az logic workflow list`
- Downloads the existing workflow definition: `az logic workflow show --query "definition"`
- Edits the JSON to inject an HTTP action that POSTs data to an attacker endpoint
- Uploads the modified definition: `az logic workflow update --definition @workflow.json`
- Grants their own identity Logic App Contributor for long-term persistence

**Injected exfiltration action example:**
- HTTP POST to attacker.example.com/collect with trigger output as body
- Runs in the context of the Logic App's managed identity
- Generates a `Microsoft.Logic/workflows/write` event in AzureActivity

**Speaker Notes:**
Walk through this attack step by step. The attacker starts with enumeration — listing all Logic Apps in the resource group. Then they download the workflow definition, which is just JSON. They inject a new HTTP action that sends data to their server. The upload generates a workflows/write event in AzureActivity — this is our primary detection signal. The final step — granting themselves Logic App Contributor — creates persistence that survives credential rotation. In the lab, students will see these AzureActivity events and trace the attack chain.

## Slide 6: Attack Vector 2 — Trigger URL Harvesting

!layout: Title and Content

HTTP-triggered Logic Apps use a SAS-signed callback URL as the trigger endpoint. This URL contains a sig= parameter that acts as a bearer secret — anyone with the URL can invoke the workflow without Azure credentials.

**Attack flow:**
- Attacker calls listCallbackUrl to retrieve the SAS-signed trigger URL
- URL format: `https://prod-xx.eastus.logic.azure.com/.../invoke?sig=<SAS_TOKEN>`
- Attacker invokes the workflow externally with curl — no Azure auth required
- Can embed trigger URL in phishing documents for victim-triggered execution

**Detection signal:** `Microsoft.Logic/workflows/triggers/listCallbackUrl/action` in AzureActivity

**Remediation:** Delete and recreate the trigger to invalidate all existing SAS URLs.

**Speaker Notes:**
This is a subtle but powerful attack vector. The SAS-signed trigger URL is essentially a bearer token for the Logic App. Once harvested, the attacker can invoke the workflow from anywhere, at any time, without any Azure credentials. They can even embed it in a phishing document so the victim triggers the workflow unknowingly. The detection signal is the listCallbackUrl operation in AzureActivity. If you see someone retrieving trigger URLs for workflows they didn't create, investigate immediately. Remediation requires regenerating the trigger URL — simply revoking the user's access doesn't invalidate existing URLs.

## Slide 7: Attack Vector 3 — Managed Identity Abuse

!layout: Title and Content

Logic Apps with managed identities can access Azure resources without explicit credentials. An attacker who edits the workflow definition redirects those managed identity calls.

| Target Resource | Common MI Permission | What Attacker Accesses |
|---|---|---|
| Azure Blob Storage | Storage Blob Data Reader | List and download all blobs |
| SharePoint / OneDrive | Sites.Read.All (Graph) | Download files from SharePoint |
| Azure Key Vault | Key Vault Secrets User | Read secrets and connection strings |
| Microsoft Graph | Mail.Read | Read mailbox contents |

**Typical adversary sequence:**
- Compromise credentials with Contributor on resource group
- Enumerate Logic Apps and their managed identity role assignments
- Download and modify a high-value workflow (one with blob/Graph/KV connectors)
- Inject HTTP exfiltration action forwarding outputs to attacker endpoint
- Retrieve trigger SAS URL for persistent, credential-free invocation

**Speaker Notes:**
This is where Logic App abuse becomes privilege escalation. The attacker may only have Contributor on the resource group, but if a Logic App's managed identity has Key Vault Secrets User, Storage Blob Data Contributor, or Graph permissions, the attacker effectively inherits those permissions by redirecting the workflow's actions. This is why separating Logic App Contributor from Managed Identity Operator roles is critical — you don't want the same identity able to both edit workflows AND assign managed identities.

## Slide 8: Detection — AzureActivity Key Operations

!layout: Title and Content

| OperationName | Meaning | Threat Signal |
|---|---|---|
| Microsoft.Logic/workflows/write | Workflow created or updated | Attacker editing workflow JSON |
| Microsoft.Logic/workflows/delete | Workflow deleted | Covering tracks or disruption |
| Microsoft.Logic/workflows/triggers/listCallbackUrl/action | Trigger SAS URL retrieved | Harvesting trigger URL |
| Microsoft.Logic/workflows/run/action | Manual workflow run initiated | Adversary-triggered execution |
| Microsoft.Authorization/roleAssignments/write | RBAC assignment added | Privilege escalation or persistence |
| Microsoft.Authorization/roleAssignments/delete | RBAC assignment removed | Covering tracks |

**Key AzureActivity fields:** Caller (who), CallerIpAddress (from where), ResourceId (which Logic App), ActivityStatus (success/fail), Authorization (RBAC action and scope)

**Speaker Notes:**
This is your detection cheat sheet for Logic App abuse. The six OperationName values cover the entire attack surface: workflow edits, deletions, trigger URL harvesting, manual runs, and RBAC changes. The Caller field shows the UPN or service principal that performed the action. CallerIpAddress shows where the call came from. Authorization contains the RBAC action and scope. Focus on workflows/write as the primary detection signal — every workflow edit generates this event. Combined with listCallbackUrl and roleAssignments/write in the same time window, you have a complete attack chain.

## Slide 9: KQL — Detect Workflow Write Operations

!layout: Title and Content

```kql
AzureActivity
| where TimeGenerated > ago(30d)
| where OperationName ==
    "Microsoft.Logic/workflows/write"
| where ActivityStatus == "Succeeded"
| project TimeGenerated, Caller,
          CallerIpAddress, ResourceId,
          ResourceGroup, SubscriptionId
| order by TimeGenerated desc
```

**What to investigate:** Any Caller that is not a known automation service principal. Interactive user accounts editing workflows are high-priority leads.

**Speaker Notes:**
This is your baseline query. Run it over 30 days to establish who normally edits Logic Apps in your environment. In a well-managed environment, workflow edits should come from DevOps pipeline service principals, not individual user accounts. Any interactive user account editing a workflow warrants investigation — they should be using the CI/CD pipeline. Look at the CallerIpAddress too — edits from unusual IPs or outside business hours are additional signals.

## Slide 10: KQL — First-Time Callers (Anomaly Detection)

!layout: Title and Content

```kql
let known_editors = AzureActivity
| where TimeGenerated between(ago(90d) .. ago(30d))
| where OperationName ==
    "Microsoft.Logic/workflows/write"
| where ActivityStatus == "Succeeded"
| summarize by Caller;

AzureActivity
| where TimeGenerated > ago(30d)
| where OperationName ==
    "Microsoft.Logic/workflows/write"
| where ActivityStatus == "Succeeded"
| where Caller !in (known_editors)
| project TimeGenerated, Caller,
          CallerIpAddress, ResourceId, ResourceGroup
| order by TimeGenerated desc
```

**What this finds:** Identities editing workflows for the first time in the last 30 days compared to a 90-day baseline — the highest-priority triage targets.

**Speaker Notes:**
This is the most effective anomaly detection query in this module. It builds a 90-day baseline of known workflow editors, then finds anyone who edited a workflow in the last 30 days who was NOT in that baseline. These first-time editors are your highest-priority investigation targets. In a mature environment, this query should return zero results most of the time — new editors should go through an onboarding process. Any result warrants immediate investigation: who is this person, why are they editing Logic Apps, and did they have authorization?

## Slide 11: KQL — Trigger URL Retrieval and RBAC Changes

!layout: Title and Content

**Detect trigger URL harvesting:**
```kql
AzureActivity
| where TimeGenerated > ago(30d)
| where OperationName has "listCallbackUrl"
| where ActivityStatus == "Succeeded"
| project TimeGenerated, Caller,
          CallerIpAddress, ResourceId, ResourceGroup
| order by TimeGenerated desc
```

**Detect RBAC changes on Logic App resources:**
```kql
AzureActivity
| where TimeGenerated > ago(30d)
| where OperationName ==
    "Microsoft.Authorization/roleAssignments/write"
| where ActivityStatus == "Succeeded"
| where ResourceId has "Microsoft.Logic/workflows"
| extend AuthJson = parse_json(Authorization)
| project TimeGenerated, Caller, CallerIpAddress,
          ResourceId,
          RoleAction = AuthJson.action,
          Scope = AuthJson.scope
| order by TimeGenerated desc
```

**Speaker Notes:**
These two queries catch the later stages of the attack. Trigger URL retrieval indicates an attacker preparing for credential-free invocation. RBAC changes on Logic App resources indicate privilege escalation or persistence. A single caller performing both a workflows/write AND a listCallbackUrl within the same session is a very strong attack signal. In the lab, we'll chain these queries together to reconstruct a complete Logic App abuse attack from workflow edit to trigger URL harvest to RBAC persistence.

## Slide 12: KQL — Full Suspicious Activity Summary

!layout: Title and Content

```kql
AzureActivity
| where TimeGenerated > ago(7d)
| where ResourceProvider == "MICROSOFT.LOGIC"
    or OperationName has
        "Microsoft.Authorization/roleAssignments"
| where ActivityStatus == "Succeeded"
| summarize
    Operations = make_set(OperationName),
    Count = count()
    by Caller, CallerIpAddress,
    ResourceGroup, bin(TimeGenerated, 1h)
| order by Count desc
```

**What to look for:** A single Caller performing multiple operation types (workflow write + trigger URL retrieval + RBAC write) within a short window — this pattern strongly indicates an adversary chain.

**Speaker Notes:**
This is the correlation query that ties everything together. It aggregates all Logic App and RBAC operations by caller across hourly windows. If you see a single caller performing 3-4 different operation types within an hour — especially the combination of workflows/write, listCallbackUrl, and roleAssignments/write — you're looking at a complete attack chain. The make_set aggregation shows exactly which operations were performed. This query is ideal for a daily hunt or an analytics rule with a 1-hour aggregation window.

## Slide 13: Incident Response

!layout: Title and Content

**Step 1 — Disable the compromised workflow:**
- `az logic workflow update --state Disabled` — stops all active runs and future triggers

**Step 2 — Revoke unauthorized RBAC assignments:**
- `az role assignment delete --assignee <attacker-id> --role "Logic App Contributor"`

**Step 3 — Invalidate trigger SAS URLs:**
- Delete and recreate the trigger — new trigger generates new sig= token
- Any exfiltrated URLs become immediately invalid

**Step 4 — Review run history:**
- Examine inputs and outputs of each action in affected runs to determine exfiltration scope

**Step 5 — Rotate secrets:**
- Replace connection strings, API keys, and storage account keys referenced by the workflow

**Speaker Notes:**
Disabling the workflow is always the first step — it stops any active exfiltration immediately. Then revoke the attacker's RBAC access. The trigger URL invalidation is critical and often missed — simply revoking the attacker's Azure credentials doesn't invalidate SAS-signed trigger URLs they may have already harvested. You must regenerate the trigger. Review the run history to understand what data was exfiltrated — Logic Apps log the inputs and outputs of every action by default (unless secure inputs/outputs are enabled). Finally, rotate any secrets the workflow had access to, since the attacker may have extracted them.

## Slide 14: Hardening Controls

!layout: Title and Content

| Control | What It Prevents |
|---|---|
| Restrict connector types via Azure Policy | Blocks HTTP connector for unauthorized data exfiltration |
| Separate Logic App Contributor from MI Operator | Prevents same user from editing workflows AND assigning managed identities |
| Store secrets in Azure Key Vault | Eliminates hardcoded secrets from workflow JSON definitions |
| Enable Secure Inputs/Outputs | Hides sensitive data from run history |
| Enable diagnostic logging (WorkflowRuntime) | Ensures AzureDiagnostics captures action-level details |
| Azure Resource Locks on production workflows | Prevents accidental or malicious modification/deletion |
| Lifecycle management | Disable Logic Apps not modified or reviewed in 90 days |

**Speaker Notes:**
The top three controls have the most impact. Azure Policy to restrict connector types prevents the HTTP exfiltration action entirely. Separating Logic App Contributor from Managed Identity Operator prevents the privilege escalation chain. Key Vault for secrets eliminates the exposure of sensitive values in workflow definitions and run history. Secure inputs/outputs should be enabled on any action that handles secrets, tokens, or PII. In the lab, students will review a Logic App's run history and see how secure inputs/outputs change the visibility of sensitive data.

## Slide 15: Key Takeaways

!layout: Title and Content

- Logic Apps combine code execution, credential access, and external connectivity — a powerful attack surface
- Three attack vectors chain together: workflow edit, trigger URL harvest, managed identity abuse
- AzureActivity is the primary detection surface — monitor workflows/write, listCallbackUrl, and roleAssignments/write
- First-time callers editing workflows are the highest-priority anomaly signal
- Invalidate trigger SAS URLs during incident response — credential revocation alone is insufficient
- Separate Logic App Contributor from Managed Identity Operator to break the privilege escalation chain

**What comes next:** Module 04 — Storage Abuse (storage key extraction, SAS token abuse, data plane log correlation)

**Speaker Notes:**
Summarize the three attack vectors and their detection signals. Emphasize that Logic App abuse is often missed because organizations focus on identity-layer monitoring and overlook resource-layer attacks. The AzureActivity table is the key — all control plane operations are logged there. Encourage students to run the first-time callers query in their production environments as a quick win. Module 04 continues the resource-layer theme with Azure Storage attacks.

## Slide 16: References

!layout: Title and Content

| Resource | Link |
|---|---|
| Azure Logic Apps Documentation | learn.microsoft.com/azure/logic-apps/logic-apps-overview |
| AzureActivity Table Schema | learn.microsoft.com/azure/azure-monitor/reference/tables/azureactivity |
| Logic App Managed Identities | learn.microsoft.com/azure/logic-apps/authenticate-with-managed-identity |
| Azure Policy for Logic Apps | learn.microsoft.com/azure/logic-apps/block-connections-connectors |
| Secure Access in Logic Apps | learn.microsoft.com/azure/logic-apps/logic-apps-securing-a-logic-app |
| Key Vault References in Logic Apps | learn.microsoft.com/azure/app-service/app-service-key-vault-references |
| MITRE ATT&CK T1648 Serverless Execution | attack.mitre.org/techniques/T1648 |

**Speaker Notes:**
The Logic Apps security documentation is comprehensive. The "Secure Access" page covers trigger access restrictions, input/output obfuscation, and managed identity configuration. The Azure Policy documentation shows how to block specific connector types at the policy level. Encourage students to review the managed identity authentication documentation and implement least-privilege RBAC in their environments.
