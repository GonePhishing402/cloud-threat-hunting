# Module 08 — Azure Web Apps (App Service): Threat Hunting & Incident Response

## Overview

Azure App Service is a fully managed platform-as-a-service (PaaS) for hosting web applications, REST APIs, and mobile backends. Because application code runs in a shared managed environment with access to Azure-managed infrastructure, the attack surface spans both the **application layer** (injection vulnerabilities, web shell deployment) and the **Azure control plane** (deployment credentials, configuration changes, managed identity abuse).

This module covers how attackers fingerprint, exploit, and pivot through App Service web apps, how defenders monitor and detect threats using Azure Monitor and Microsoft Defender for App Service, and how to execute a structured incident response.

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Active Scanning: Vulnerability Scanning | T1595.002 | Fingerprinting web apps via response headers (runtime, version) |
| Exploit Public-Facing Application | T1190 | OS command injection via unsanitized shell commands in app code |
| Command and Scripting Interpreter | T1059 | Executing arbitrary commands via `exec()`, `system()`, `shell_exec()` |
| Unsecured Credentials: Credentials in Environment Variables | T1552.001 | Harvesting secrets and connection strings from `env` after RCE |
| Steal Application Access Token | T1528 | Querying IMDS for managed identity OAuth tokens |
| Valid Accounts: Cloud Accounts | T1078.004 | Using stolen managed identity tokens to access downstream Azure resources |
| Cloud Service Discovery | T1526 | Enumerating subscription ID, resource group, and region from env vars |
| Server Software Component: Web Shell | T1505.003 | Deploying PHP/ASPX web shells to `wwwroot` via FTP or Kudu |

---

## Key Log Tables

| Table | Description |
|---|---|
| `AppServiceHTTPLogs` | Web server HTTP requests — method, URI, status code, client IP, user agent |
| `AppServiceConsoleLogs` | Standard output/error from the application — RCE evidence |
| `AppServiceAppLogs` | Application-level traces, errors, and warnings |
| `AppServiceAuditLogs` | FTP and Kudu login activity |
| `AppServiceFileAuditLogs` | File writes/creates to site content (Premium tier) — web shell detection |
| `AppServiceIPSecAuditLogs` | Requests evaluated against IP restriction rules |
| `AppServicePlatformLogs` | Container start/stop/pull events (Linux/Container workloads) |
| `AzureActivity` | Control plane operations — deployments, config writes, stops, restarts |

---

## Key Attack Scenarios

1. **OS Command Injection → RCE** — User-controlled input passed to `exec()`, `system()`, or equivalent without sanitization; attacker injects `$(id)` / `$(env)` to confirm execution and dump secrets
2. **Managed Identity Token Theft** — After RCE, attacker reads `IDENTITY_ENDPOINT` + `IDENTITY_HEADER` from env vars and queries IMDS to obtain OAuth tokens for ARM, Key Vault, Storage, or Graph
3. **Auth Token Forgery** — `WEBSITE_AUTH_SIGNING_KEY` extracted from env vars and used to forge App Service Easy Auth session tokens, bypassing authentication entirely
4. **Web Shell via Kudu/FTP** — Attacker uses leaked or brute-forced publishing credentials to upload a PHP/ASPX web shell to `wwwroot`, establishing persistent RCE
5. **Subdomain Takeover via Dangling DNS** — Decommissioned App Service still has a live DNS `CNAME`; attacker registers the same hostname to serve phishing or malicious content at the trusted domain

---

## Module Files

| File | Description |
|---|---|
| [Attack.md](Attack.md) | Attacker perspective: fingerprinting, RCE, env var harvesting, token theft, attack scenarios |
| [Defend.md](Defend.md) | Logging configuration, KQL queries, alert rules, Defender for App Service |
| [Mitigate.md](Mitigate.md) | NIST-aligned IR playbook: detection, containment, recovery, hardening |

---

## Prerequisites

- Azure subscription with App Service web apps deployed
- Log Analytics workspace connected via diagnostic settings
- Microsoft Defender for App Service enabled (Standard plan)
- App Service on **Premium tier or above** for `AppServiceFileAuditLogs`
- Microsoft Sentinel (optional — for automated playbooks)
- `az` CLI for containment and recovery commands

---

## References
- [Azure App Service Documentation](https://learn.microsoft.com/azure/app-service/)
- [Monitor Azure App Service](https://learn.microsoft.com/azure/app-service/monitor-app-service)
- [Secure Your Azure App Service Deployment](https://learn.microsoft.com/azure/app-service/overview-security)
- [Defender for App Service Overview](https://learn.microsoft.com/azure/defender-for-cloud/defender-for-app-service-introduction)
- [Alerts for Azure App Service](https://learn.microsoft.com/azure/defender-for-cloud/alerts-azure-app-service)
- [App Service Environment Variables Reference](https://learn.microsoft.com/azure/app-service/reference-app-settings)
- [Managed Identities for App Service](https://learn.microsoft.com/azure/app-service/overview-managed-identity)
- [Prevent Dangling DNS and Subdomain Takeover](https://learn.microsoft.com/azure/security/fundamentals/subdomain-takeover)
