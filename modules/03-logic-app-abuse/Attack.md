# Attack - Module 03 (Logic App Abuse)

## Attack Patterns

1. Data exfiltration via outbound connectors and HTTP actions.
2. Privilege abuse through over-privileged managed identities.
3. Persistence using recurrence triggers and hidden automation paths.

## Typical Adversary Sequence

- Gain permission to create or edit workflows.
- Add connectors/actions that move sensitive data externally.
- Bind a managed identity with broader rights than workflow intent.
- Schedule recurring runs for persistent exfiltration.

## High-Signal Indicators

- Unexpected workflow creation or edits by non-automation personas.
- New external callback URLs/endpoints used by workflows.
- Managed identity usage that exceeds intended scope.

## Microsoft Learn References

- Secure access and data for workflows: https://learn.microsoft.com/azure/logic-apps/logic-apps-securing-a-logic-app
- Managed identity auth in Logic Apps: https://learn.microsoft.com/azure/logic-apps/authenticate-with-managed-identity
- Logic Apps security baseline: https://learn.microsoft.com/security/benchmark/azure/baselines/logic-apps-security-baseline
