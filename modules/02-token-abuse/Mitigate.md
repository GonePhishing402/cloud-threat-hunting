# Mitigate - Module 02 (Token Abuse)

## Incident Mitigation Playbook

1. Revoke active sessions and require reauthentication.
2. Block high-risk users or require immediate secure password reset.
3. Constrain sign-ins to trusted locations/compliant networks.
4. Isolate compromised devices and remove malware footholds.

## Recovery and Hardening

- Expand token protection coverage for supported applications.
- Add authentication context for high-impact actions.
- Tune analytics for anomalous non-interactive and refresh behavior.
- Validate that incident closure includes endpoint and identity remediation.

## Verification

- No repeated replay indicators from previously malicious IPs.
- User and sign-in risk return to expected baseline.
- Sentinel detection-to-response time decreases for token scenarios.

## Microsoft Learn References

- Token theft detection and mitigation: https://learn.microsoft.com/entra/identity/devices/protecting-tokens-microsoft-entra-id
- Token protection: https://learn.microsoft.com/entra/identity/conditional-access/concept-token-protection
- Token theft playbook: https://learn.microsoft.com/security/operations/token-theft-playbook
