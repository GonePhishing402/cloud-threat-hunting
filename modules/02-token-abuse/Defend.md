# Defend - Module 02 (Token Abuse)

## Defensive Controls

- Enforce device compliance and endpoint hardening.
- Enforce risk-based Conditional Access and interactive reauthentication for sensitive actions.
- Pilot and deploy token protection for supported apps and platforms.
- Apply network-based restrictions for sign-in and app session replay resistance.

## Detection Objectives

1. Catch token theft attempts at endpoint and identity layers.
2. Detect replay from non-compliant or non-trusted networks.
3. Trigger automatic user/session containment on high risk.

## Practical Defensive Baseline

- Microsoft Defender for Endpoint + Intune compliance.
- Identity Protection risk policies.
- CAE-aware policy enforcement where supported.

## Microsoft Learn References

- Protecting tokens in Microsoft Entra: https://learn.microsoft.com/entra/identity/devices/protecting-tokens-microsoft-entra-id
- Continuous Access Evaluation: https://learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation
- Risk-based Conditional Access: https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies
