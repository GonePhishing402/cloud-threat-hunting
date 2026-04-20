# Mitigate - Module 00 (Threat Hunt Methodology)

## Program-Level Mitigation Plan

Use this plan when hunts uncover real attacker behavior:

1. Immediate: confirm scope, create incident, contain active access path.
2. Short term: convert successful hunt query into analytics rule and automation.
3. Long term: update threat model, improve logging coverage, and tune detections.

## Standard Response Loop

- Preserve evidence with bookmarks and incident annotations.
- Map findings to ATT&CK tactics and affected cloud assets.
- Identify missing telemetry and enable diagnostic settings where needed.
- Track closure criteria and retest with emulated data.

## Success Criteria

- Each high-value hunt has one mapped detection or documented decision.
- Repeated attack paths show decreasing time-to-detect.
- Logging blind spots are remediated as tracked engineering actions.

## Microsoft Learn References

- Threat hunting in Microsoft Sentinel: https://learn.microsoft.com/azure/sentinel/hunting
- Create custom analytics rules: https://learn.microsoft.com/azure/sentinel/detect-threats-custom
- Connect services via diagnostic settings: https://learn.microsoft.com/azure/sentinel/connect-services-diagnostic-setting-based
