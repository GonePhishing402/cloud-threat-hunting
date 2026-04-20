# Attack - Module 06 (Hardening Capstone)

## Composite Adversary Model

This capstone models chained cloud attacks across identity, automation, and data planes:

1. Gain access through phishing or token abuse.
2. Establish persistence through workload identities.
3. Abuse automation and data services for stealthy exfiltration.

## Why This Matters

Single-point controls fail when attackers pivot across services. Capstone attack modeling should test:

- Cross-subscription visibility.
- Identity-to-data pivot paths.
- Detection and response handoff quality.

## Simulation Focus

- Illicit consent or token replay as entry.
- Logic App or identity persistence as foothold.
- Storage/Key Vault abuse as collection and exfiltration path.

## Microsoft Learn References

- Microsoft cloud security benchmark - identity management: https://learn.microsoft.com/security/benchmark/azure/mcsb-v2-identity-management
- Threat hunting in Microsoft Sentinel: https://learn.microsoft.com/azure/sentinel/hunting
- Connect data sources to Microsoft Sentinel: https://learn.microsoft.com/azure/sentinel/connect-data-sources
