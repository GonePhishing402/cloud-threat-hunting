# Attack - Module 00 (Threat Hunt Methodology)

## Adversary View

This module does not emulate one specific technique. Instead, it frames how attackers chain tactics across cloud control planes:

1. Initial foothold through phishing, token theft, or consent abuse.
2. Privilege expansion through role assignment, app credentials, or managed identities.
3. Data access/exfiltration through storage, Key Vault, and automation services.

## Hunt-Driven Attack Modeling

Use a hypothesis-first method to model likely cloud attacks:

- Start from MITRE ATT&CK tactic gaps that have weak visibility.
- Identify required tables before building any query.
- Run and tune hunts weekly, not only after incidents.
- Track result deltas to detect behavior spikes, then escalate into analytics rules.

## ATT&CK Mapping Focus

- Initial Access
- Credential Access
- Persistence
- Defense Evasion
- Collection
- Exfiltration

## Microsoft Learn References

- Threat hunting in Microsoft Sentinel: https://learn.microsoft.com/azure/sentinel/hunting
- Conduct end-to-end hunts in Microsoft Sentinel: https://learn.microsoft.com/azure/sentinel/hunts
- Create and publish hunting queries: https://learn.microsoft.com/azure/sentinel/sentinel-hunting-rules-creation
