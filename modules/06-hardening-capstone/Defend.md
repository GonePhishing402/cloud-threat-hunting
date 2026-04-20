# Defend - Module 06 (Hardening Capstone)

## Defense-in-Depth Objectives

- Centralize identity and authentication controls.
- Secure non-human identities and secret management.
- Enforce conditional, least-privilege access.
- Ensure high-fidelity logging for detection coverage.

## Prioritization Model

1. Identity controls with highest blast-radius reduction.
2. Data protection controls that reduce exfiltration risk.
3. Automation/workload controls that reduce persistence opportunities.
4. Detection engineering controls that reduce dwell time.

## Minimum Defensive Baseline

- MFA and phishing-resistant methods for privileged users.
- Managed identities over static secrets where feasible.
- Conditional access and risk policies for high-risk sign-ins.
- Sentinel detections for consent, token, workload identity, and data abuse.

## Microsoft Learn References

- MCSB identity controls: https://learn.microsoft.com/security/benchmark/azure/mcsb-v2-identity-management
- Zero Trust identity protection guidance: https://learn.microsoft.com/entra/fundamentals/zero-trust-protect-identities
- Sentinel best practices for data collection: https://learn.microsoft.com/azure/sentinel/best-practices-data
