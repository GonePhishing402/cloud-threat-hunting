# Attack - Module 02 (Token Abuse)

## Attack Patterns

1. Access/refresh token theft and replay from attacker infrastructure.
2. Session artifact replay after AiTM or endpoint compromise.
3. PRT-adjacent abuse where attacker attempts to bypass normal reauthentication controls.

## Typical Adversary Sequence

- Steal tokens from browser cache, client tools, or compromised endpoints.
- Replay tokens from unmanaged or unexpected networks.
- Maintain persistence by repeatedly refreshing or reusing session artifacts.

## High-Signal Indicators

- Same identity authenticating from divergent locations in short windows.
- Non-interactive refresh patterns inconsistent with user baseline.
- Risk detections such as anomalous token behavior and unfamiliar sign-in properties.

## Microsoft Learn References

- Protecting tokens in Microsoft Entra: https://learn.microsoft.com/entra/identity/devices/protecting-tokens-microsoft-entra-id
- Understanding tokens in Microsoft Entra ID: https://learn.microsoft.com/entra/identity/devices/concept-tokens-microsoft-entra-id
- Token protection in Conditional Access: https://learn.microsoft.com/entra/identity/conditional-access/concept-token-protection
