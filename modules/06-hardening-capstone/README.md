# Module 06 — Hardening Capstone

## Objective

Synthesize all hardening knowledge from Modules 01–05 into a defense-in-depth assessment. Students evaluate an Azure environment configuration, identify security gaps, and build a prioritized remediation plan with Sentinel detection rules and automated response playbooks.

## Duration

~3 hours (scenario-based assessment + group exercise)

## Module Structure

This module is **scenario-driven** — no new attack content is introduced. Instead, students apply everything they've learned to evaluate and harden a realistic Azure environment.

## Scenario

Students receive a simulated Azure environment configuration (JSON/Bicep) representing a mid-size organization with:
- 500 Azure AD users across 3 departments
- 2 subscriptions (Production, Development)
- 12 service principals with varying permission levels
- 5 storage accounts, 2 Key Vaults
- 3 Logic Apps
- Conditional Access policies (partially configured)
- Diagnostic settings (partially enabled)

**The environment has intentional security gaps across all module domains.**

## Defense-in-Depth Checklist

### Identity & Access
| Control | Status Check | Maps to Module |
|---|---|---|
| Admin consent workflow enabled | `AuditLogs \| where OperationName == "Consent to application"` | 01 - Phishing |
| Phishing-resistant MFA enforced for admins | Conditional Access policy review | 01 - Phishing |
| Device code flow restricted | Conditional Access - Other clients blocked | 01 - Phishing |
| CAE enabled | Security defaults / CA session controls | 02 - Token Abuse |
| Token lifetime policies configured | Token configuration review | 02 - Token Abuse |
| SP credential expiration < 6 months | `AuditLogs` credential review | 05 - Persistence |
| Federated identity credentials reviewed | Approved issuer list | 05 - Persistence |
| PIM enabled for privileged roles | Azure AD PIM status | Cross-cutting |

### Data Protection
| Control | Status Check | Maps to Module |
|---|---|---|
| Storage shared key access disabled | `AllowSharedKeyAccess = false` | 04 - Storage/KV |
| Storage private endpoints configured | Network rules review | 04 - Storage/KV |
| Key Vault RBAC (not access policies) | Access model review | 04 - Storage/KV |
| Key Vault soft-delete + purge protection | KV properties review | 04 - Storage/KV |
| Key Vault private endpoints | Network rules review | 04 - Storage/KV |
| Secret rotation automated | Rotation policy review | 04 - Storage/KV |

### Compute & Automation
| Control | Status Check | Maps to Module |
|---|---|---|
| Logic App connectors restricted | Azure Policy review | 03 - Logic Apps |
| Logic App MI permissions scoped | RBAC review | 03 - Logic Apps |
| Managed identity lifecycle management | MI audit, unused MI identification | 05 - Persistence |
| Unused Logic Apps disabled | Resource inventory review | 03 - Logic Apps |

### Logging & Detection
| Control | Status Check | Maps to Module |
|---|---|---|
| Azure AD sign-in logs → Sentinel | Diagnostic settings | 07 - Logging |
| Azure AD audit logs → Sentinel | Diagnostic settings | 07 - Logging |
| Azure Activity logs → Sentinel | Subscription diagnostic settings | 07 - Logging |
| Storage data plane logs enabled | Storage diagnostic settings | 04 & 07 |
| Key Vault audit logs enabled | KV diagnostic settings | 04 & 07 |
| Logic App runtime logs enabled | Logic App diagnostic settings | 03 & 07 |
| SP sign-in logs enabled | AADServicePrincipalSignInLogs | 05 & 07 |

## Conditional Access Policy Matrix

Students build/validate a CA policy set covering:

| Policy | Grant | Session | Target |
|---|---|---|---|
| Require MFA for all users | MFA | | All cloud apps |
| Require phishing-resistant MFA for admins | Authentication strength: Phishing-resistant | | Admin roles |
| Block device code flow | Block | | All users |
| Require compliant device for M365 | Compliant device | | Office 365 |
| CAE enforcement | | Customize CAE: Strictly enforce | All cloud apps |
| Token protection for sensitive apps | | Require token protection | SharePoint, Exchange |
| Block legacy authentication | Block | | All users, Other clients |
| Restrict admin portal access | MFA + compliant device | | Microsoft Admin Portals |

## Sentinel Analytics Rule Pack

Deploy these rules as part of the capstone exercise:

1. **Illicit Consent Grant Detection** — Alert on user consent to apps with high-privilege scopes
2. **AiTM Session Replay** — Alert on MFA success followed by token use from different IP
3. **Device Code Anomaly** — Alert on device code auth by non-baseline users
4. **Token Replay Fast** — Alert on token use from >2 distinct IPs within 10 minutes
5. **Logic App External HTTP** — Alert on Logic App runs with HTTP connector to external IPs
6. **Storage Key Listing** — Alert on `listKeys` operations from non-automation accounts
7. **Key Vault Enumeration** — Alert on >3 distinct SecretGet operations in 15 minutes
8. **SP Credential Addition** — Alert on new credentials added to service principals
9. **Federated Identity Credential** — Alert on any new federated identity credential
10. **High-Privilege App Role Assignment** — Alert on directory-level app role grants

## CTFd Challenges

| # | Title | Difficulty | Description |
|---|---|---|---|
| 1 | Gap Finder | Easy | Given the environment config, identify 3 missing Conditional Access policies |
| 2 | Logging Blind Spots | Medium | Identify which attack modules would be undetectable given the current logging config |
| 3 | Priority Matrix | Medium | Rank the top 5 hardening actions by risk reduction impact |
| 4 | Rule Builder | Hard | Deploy 3 Sentinel analytics rules and validate they detect the emulated attack data |
| 5 | Full Assessment | Hard | Complete the defense-in-depth checklist and produce a hardening report |

## Group Exercise

**Duration:** 45 minutes + 15 minute presentations

Teams of 3–4 students receive the environment configuration and must:
1. Complete the defense-in-depth checklist (identify all gaps)
2. Prioritize the top 5 remediation actions with justification
3. Deploy at least 2 Sentinel analytics rules from the rule pack
4. Present findings and recommendations to the class

**Scoring:** Presentation quality (25%), gap identification completeness (25%), prioritization rationale (25%), working analytics rules (25%)
