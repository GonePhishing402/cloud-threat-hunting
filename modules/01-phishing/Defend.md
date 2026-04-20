# Defend - Module 01 (Phishing in Cloud Identity)

## Defensive Controls

- Enforce phishing-resistant authentication methods.
- Restrict user consent and require governance for OAuth app permissions.
- Block device code flow unless there is a documented business exception.
- Require compliant devices and risk-based Conditional Access.

## Control Priorities

1. Require phishing-resistant MFA for privileged users first.
2. Disable broad user consent and allow only verified publisher models.
3. Add policies for sign-in risk and user risk.
4. Monitor OAuth app and sign-in anomalies in Sentinel.

## Detection Objectives

- Detect suspicious consent activity quickly.
- Detect replay behaviors (new IP, atypical session patterns).
- Detect risky device code use by non-baseline users.

## Microsoft Learn References

- Phishing-resistant authentication: https://learn.microsoft.com/entra/identity/authentication/overview-authentication
- Detect and remediate illicit consent grants: https://learn.microsoft.com/defender-office-365/detect-and-remediate-illicit-consent-grants
- Protecting tokens in Microsoft Entra: https://learn.microsoft.com/entra/identity/devices/protecting-tokens-microsoft-entra-id
