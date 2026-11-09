# Telemetry, prerequisites and trust boundaries

## Data flow

Native Microsoft connectors → Sentinel tables → explicit watchlist mappings → scheduled analytics → Sentinel incidents and workbook.

Optional trusted producer → authenticated Azure Monitor Logs Ingestion API → DCR → `AIAgentEvent_CL` → optional session correlations.

The pack does not intercept, block or modify agent actions. Keep Entra, Purview and Defender preventive controls enabled. Do not duplicate prompt classifiers with keyword-only rules.

## Native sources

| Source | Sentinel table | Required setup and limitations |
|---|---|---|
| Power Platform administrative audit | `PowerPlatformAdminActivity` | Enable the supported Power Platform audit ingestion path and validate that Copilot Studio operations are present. Merely enabling the Office 365 connector does not guarantee these events. Validate `Properties.BotId` / `PropertyCollection.BotId` with real tenant samples; records without a resolvable agent ID cannot be reliably joined. |
| Entra audit | `AuditLogs` | Stream audit diagnostic logs to the workspace. Validate operation names and TargetResources modifiedProperties for permission changes. These are not agent-session traces. |
| Entra workload identity sign-ins | `AADServicePrincipalSignInLogs` | Enable service-principal sign-in ingestion. Map service principal object IDs, not display names or app IDs interchangeably. A successful sign-in is not proof of resource access or data theft. |
| Defender for Endpoint | `DeviceProcessEvents`, `DeviceNetworkEvents` | Connect Defender XDR raw advanced hunting tables to Sentinel, not only alerts/incidents. Devices must be onboarded and reporting. Requires precise runtime inventory. These tables do not prove arbitrary sensitive-file reads. |
| Security alerts | `SecurityAlert` | Connect relevant security products. The workbook displays pack alerts and links supporting native investigation. Native agent detection features may be preview or require additional configuration. |

Do not hard-code Copilot Studio agent authoring into `OfficeActivity` without checking the actual connector route. Audit metadata is not a full conversation transcript. Authentication updates do not automatically mean authentication was weakened. Change records can be emitted multiple times at the SDK layer; analytics deduplicate by stable event ID where available.

### Native payload checks before rule enabling

1. Identify real creation, publication and authentication-update events and confirm operation spelling, result values, event ID and BotId placement.
2. Compare normalized agent IDs across inventory and audit; do not join only by display name.
3. Compare both Entra app IDs and service-principal object IDs against the inventory.
4. Verify exact endpoint paths from `InitiatingProcessFolderPath`; this field represents the full executable path in the Windows endpoint schema, not just a parent directory.
5. Verify DeviceId, process creation time and PID linkage across native endpoint events. Shared runtimes must not be attributed to one agent.
6. Execute each full query and inspect returned evidence, not only compilation results.
7. Review source latency, historical retention, event volumes, regional support and licenses.

Native schema references:

- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/powerplatformadminactivity
- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs
- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs
- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table
- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table
- https://learn.microsoft.com/en-za/microsoft-copilot-studio/admin-logging-copilot-studio
- https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/ai-agent-detection-protection

## Optional normalized agent events

**Not required for native rules. No telemetry SDK, MCP proxy or producer is bundled in this release.** This module provides an explicit table/ingestion schema and two correlation use cases for organizations that can produce suitable, trustworthy events. It must not be advertised as automatic native Defender conversion.

`arm\optional-telemetry.json` creates a 30-day Analytics custom table, DCE and DCR in the workspace resource group/region. The endpoint permits public network access and is protected by Azure authentication/RBAC; review private-link requirements before deployment. This module does not configure private endpoints, assign roles, or create credentials. Retention, ingestion and Azure resource costs are customer responsibilities.

| Column | Type | Contract |
|---|---|---|
| TimeGenerated | datetime | UTC event time, close to ingestion time. The producer must reject impossible future times and unbounded clock skew. |
| EventId | string | Nonempty stable producer event identifier. Retries reuse the same value. |
| AgentId | string | Stable agent identity matching the enabled inventory; never a friendly-name guess. |
| SessionId | string | Nonempty opaque session identifier, unique per agent session. Do not recycle across executions. |
| EventType | string | `InjectionSignal`, `ToolInvocation`, `DataAccess`, `ExternalSubmission` or `Heartbeat`. |
| ActorUPN | string | Human UPN when reliably known; otherwise empty. |
| ToolName | string | Stable tool identifier, not untrusted content. |
| DestinationHost | string | Lowercase exact hostname, without URL path, credentials, port or query string. |
| DataClassification | string | `Public`, `Internal`, `Confidential`, `HighlyConfidential`, or empty/unknown. Must come from a reliable source classification. |
| Outcome | string | `Succeeded`, `Blocked`, `Failed` or `Unknown`. Do not relabel an attempted or blocked submission as successful. |
| ResourceId | string | Safe, minimal resource identifier. Strip secrets and personal data. |
| CorrelationId | string | Tool/action/data-flow correlation when available. A session match alone is not causal proof. |
| Evidence | string | Short redacted source context or native evidence reference. Never raw prompts, documents, credentials or tool arguments. |
| SchemaVersion | string | `1.0`; update the mapping and rules before introducing incompatible versions. |

The DCR enforces column types, **not these semantic or enum constraints**. The producer must enforce them. Optional queries reject unsupported schema versions and incomplete identifiers. Access to the ingestion DCR is a trust boundary: a malicious producer can forge events. Limit producer scope and monitor writes.

### Producer onboarding

1. Deploy `OptionalTelemetry` and inspect the DCE's `properties.logsIngestion.endpoint` and DCR's `properties.immutableId` in Azure.
2. Grant only the producer's managed identity the **Monitoring Metrics Publisher** role at the **DCR resource scope**, following Azure Monitor Logs Ingestion API documentation. Do not grant subscription Owner or embed a client secret.
3. Acquire a managed-identity token for the Azure Monitor audience (`https://monitor.azure.com/`).
4. Submit JSON event arrays via HTTPS POST to `{logsIngestionEndpoint}/dataCollectionRules/{immutableId}/streams/Custom-AIAgentEvent?api-version=2023-01-01` with bearer authorization. Stream names are case-sensitive.
5. Start with a synthetic `Heartbeat`, confirm `SchemaVersion`, IDs and timestamp in Logs, then replay safe ordered sessions. Never send actual secrets as a test.
6. Add a source-grounded `InjectionSignal` adapter only if the originating product exposes trustworthy detection evidence. Preserve native alert references. Neither an agent saying it detected an injection nor a keyword match is sufficient evidence on its own.
7. Verify exactly what a `DataAccess` and an `ExternalSubmission` mean in the producer. Classification and session linkage alone do not prove that the same data was transmitted; retain exact-flow correlation when available.
8. Deploy optional rules disabled; review signal quality and false positives before enabling.

Reference: https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview

## Telemetry health

The workbook uses a fuzzy union with a typed empty branch so unavailable optional tables can be omitted. Missing-table warnings may remain visible in Logs/workbooks. Native page queries still require their actual native sources; those errors are useful prerequisite signals, not hidden as healthy.

`NOT OBSERVED` means a missing table, no records, or no records in the selected window. `STALE` uses a two-hour advisory threshold, not a universal SLA. `RECEIVING` proves recent records only, not complete agent coverage. Do not alert on source silence without source-specific expected cadence, historical baseline, ingestion delay and maintenance handling.

Rule scheduling uses event-time windows; overlapping runs can produce repeated findings. Sentinel incident grouping is disabled by default to avoid merging unrelated agents. Tune grouping, suppression and lateness handling only after measuring tenant ingestion behavior. Severe late arrivals beyond configured query periods are not covered.
