# Mitigate - Module 01 (Phishing in Cloud Identity)

## Incident Mitigation Playbook

1. Revoke malicious OAuth grants and app role assignments.
2. Block sign-in for impacted identities when risk is active.
3. Revoke sessions/tokens and force reauthentication.
4. Contain mail/data access abuse paths and investigate downstream actions.

## Recovery and Hardening

- Remove or disable untrusted applications.
- Tighten consent governance and Conditional Access controls.
- Validate token replay protections and network/location restrictions.
- Add or tune Sentinel analytics for consent and replay behaviors.

## Verification

- Confirm no further suspicious app consent or replay alerts.
- Confirm affected users show clean sign-in risk posture.
- Confirm detections produce incidents with clear triage steps.

## Microsoft Learn References

- Illicit consent response: https://learn.microsoft.com/defender-office-365/detect-and-remediate-illicit-consent-grants
- Remove OAuth grants (Graph PowerShell): https://learn.microsoft.com/powershell/module/microsoft.graph.identity.signins/remove-mgoauth2permissiongrant
- Token theft mitigation strategy: https://learn.microsoft.com/entra/identity/devices/protecting-tokens-microsoft-entra-id
