# Analyst response and containment

No automatic containment playbook is deployed. Identity disablement, agent unpublishing and credential revocation can interrupt production. This release supplies investigation guidance; automate only after establishing authorization, supported APIs, least privilege and rollback procedures.

## Triage

1. Confirm source ingestion, rule version and enabled watchlist mappings. Record AgentId, event IDs, UTC times, creator/actor, environment, device and service principal identifiers.
2. Determine whether this is a configuration finding, anomalous behavior, or a verified harmful outcome. Do not report an authentication update as an authentication downgrade without examining old/new settings.
3. Open original Power Platform, Entra, Defender and Purview evidence in their protected portals. Check owner approval, deployment records, change windows and approved automation.
4. Trace the chain: creator → agent → mapped identity/runtime → tool/resource → destination → observed result. Mark inferred edges and missing evidence. A sign-in does not establish sensitive-data access; a network connection does not establish payload exfiltration.
5. For optional events, verify producer identity and original alert/action evidence. Distinguish blocked attempts from successful actions and exact action correlation from session-only proximity.
6. Check other agents sharing the same environment, connector, owner or vulnerable dependency without assuming a common attacker.

## Containment choices requiring human approval

- Unpublish or disable the affected agent through the supported platform control, after preserving evidence and confirming business ownership.
- Restrict or revoke the mapped workload identity's excessive permissions. Disabling a service principal can affect multiple applications; verify scope first.
- Rotate or revoke exposed secrets at the source and audit subsequent use. Do not copy secrets into incidents, watchlists or this repository.
- Isolate a confirmed compromised endpoint using Defender's authorized incident-response workflow, not a workbook-side command.
- Revert a verified malicious agent/tool configuration to a reviewed version; preserve previous versions and deployment provenance.
- Block a confirmed malicious destination with an appropriate network/security control. Do not block all external tool traffic based on novelty alone.

## Evidence and recovery

Preserve immutable event references, relevant versions and UTC timestamps. Keep full transcripts and sensitive content in authorized native evidence stores, not in a broadly shared workbook. Follow legal retention requirements. Validate the corrected agent with synthetic data, re-evaluate inventory ownership and permissions, then restore access gradually and monitor recurrence.

## Noise and duplicate management

Native Defender detections should remain the authoritative alert when they already establish the same behavior. Link or group custom correlation incidents only when shared stable agent/action evidence supports it. Do not generate a second incident for every native alert. Monitor false-positive rate, recurring approved changes, source latency, and query cost before enabling broad rule sets.
