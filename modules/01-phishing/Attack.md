# Attack - Module 01 (Phishing in Cloud Identity)

## Attack Patterns

1. Illicit consent grants to malicious OAuth apps.
2. Adversary-in-the-middle (AiTM) session theft and replay.
3. Device code phishing through user-driven code entry.

## Typical Adversary Sequence

- Trick user into consent or interactive authentication.
- Reuse tokens/session artifacts without needing password reset bypass.
- Access data via Graph, M365, or cloud apps as valid account activity.

## High-Signal Indicators

- Unexpected "Consent to application" events.
- New risky OAuth apps with broad scopes.
- Impossible travel/session reuse behavior after MFA.
- Device code sign-ins for users who normally do not use device code flow.

## Microsoft Learn References

- Detect and remediate illicit consent grants: https://learn.microsoft.com/defender-office-365/detect-and-remediate-illicit-consent-grants
- Protecting tokens in Microsoft Entra: https://learn.microsoft.com/entra/identity/devices/protecting-tokens-microsoft-entra-id
- Authentication flows (device code flow): https://learn.microsoft.com/entra/identity/conditional-access/concept-authentication-flows#device-code-flow
