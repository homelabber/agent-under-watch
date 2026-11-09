# Detection behavior and prerequisites

## Release boundary

`catalog\rules.json` is the authoritative array of eight scheduled analytics definitions: six native signals and two explicitly optional custom-event correlations. All are **disabled by default**. Nothing deploys or enables cloud resources merely by reading these files. Query files are plain KQL, not templates. Frequencies are 15 minutes; periods are one hour except the 14-day destination baseline. `TimeGenerated`, `AgentId`, `ActorUPN`, `Evidence`, and `CorrelationQuality` are emitted by every rule. `ActorUPN` may be empty when a native actor is not a user principal. Evidence contains identifiers and concise assessments, not raw prompts, tokens, command lines, or file contents.

Native telemetry can support configuration changes, process/network behavior and identity authentication. It cannot establish prompt injection, permission use, arbitrary file reads, successful data theft or a particular agent session. Exact joins are not proof of malicious causation. `exact` means a deterministic agent/actor/environment event sequence; `configuration` means an observed audit change; `heuristic` marks runtime attribution or temporal/trace association. These values do not score threat certainty.

The only ATT&CK tactic assigned is **Execution** for directly observed shell/script-host execution. Configuration review, destination novelty and optional prompt/data associations intentionally have no tactic mappings. No AI-native Microsoft table is assumed. `OfficeActivity` is not a substitute for `PowerPlatformAdminActivity` here.

## Connector and watchlist setup

1. Ingest Power Platform administrator activity into `PowerPlatformAdminActivity` using the supported Power Platform/Sentinel audit collection configuration for the tenant. Enable the underlying auditing and required licensing/permissions. Verify Copilot Studio operations actually arrive; connector enablement alone does not prove coverage. This is not a dependency on a hypothetical Copilot interaction table.
2. Use the Microsoft Entra ID connector and appropriate diagnostic categories for `AuditLogs` and, for the sign-in sequence only, `AADServicePrincipalSignInLogs` (service-principal sign-in logs). Managed identity sign-ins are a different source and are not silently included. Licensing, retention and category availability must be checked locally.
3. For endpoint rules, enable the Microsoft Defender XDR connector's raw Defender for Endpoint event collection into `DeviceProcessEvents` and `DeviceNetworkEvents`. Alerts-only ingestion is insufficient. Endpoint onboarding and retention must cover the registered runtime and baseline. Cloud-hosted Copilot Studio does not automatically run on an enrolled endpoint; only explicitly registered self-hosted runtime processes are covered.
4. Create all rule-specific watchlists using the exact aliases below, then replace disabled seed rows with validated real inventory. IDs, UPNs, filenames and Windows paths compare case-insensitively. There is no fuzzy agent/display-name matching and no AppId-to-object-ID inference. All rules except rapid creation/publication require enabled known-agent inventory; empty inventory or disabled rows cannot generate their results. The creation/publication rule deliberately includes unregistered observed BotIds and uses inventory only for registration-status enrichment. Missing tables/watchlists are **prerequisite failures**, not quiet success: resolve them before enabling rules.

| Alias | Required contract |
|---|---|
| `AIAgentInventory` | SearchKey=`AgentId`; AgentId, AgentName, ServicePrincipalObjectId, AppId, OwnerUPN, Criticality, Enabled |
| `AIAgentApprovedMakers` | SearchKey=`ActorUPN`; ActorUPN, EnvironmentId, Enabled; `*` is allowed only as an environment-wide approval |
| `AIAgentRuntimeInventory` | SearchKey=`RuntimeKey`; RuntimeKey, AgentId, DeviceId, ProcessFileName, ProcessFolderPath, Enabled |
| `AIAgentAllowedDestinations` | SearchKey=`AgentId`; AgentId, DestinationHost, Enabled |

Only literal `Enabled=true` (case-insensitive) is active. IDs must be canonical without surrounding whitespace. Use service-principal **object** IDs, not application/client IDs. Runtime paths must exactly match the native `InitiatingProcessFolderPath` value; do not assume a directory or executable path transformation, wildcard, slash conversion or environment expansion. Register a unique agent per device/path tuple where possible; shared runtimes can attribute one event to multiple agents. Parent-path matching cannot prove a trustworthy executable or isolate a session.

Destination entries are exact lowercase-compatible DNS/punycode hosts without scheme, slash, port, wildcard, surrounding whitespace or credentials. Trailing dots are removed. Subdomains are not approved by a parent domain entry. Destination-dependent rules require at least one valid enabled destination entry **per agent**, so an empty/invalid policy is not interpreted as deny-all. This guard does not verify that an operator's nonempty policy is complete. Keep inventory and policy changes under change control: evaluation uses current watchlists, not historical snapshots.

## Native rules

### rapid-unapproved-publish

Requires `PowerPlatformAdminActivity`, inventory and approved-maker watchlists. Deduplicates by nonempty `EventOriginalUid`; accepts only `EventResult=Succeeded`. Matches `BotCreate` to `BotUpdateOperation-BotPublish` for the same observed nonempty `BotId`, same UPN-valued `ActorName`, and same nonempty `EnvironmentId`, with publication at or after creation and within 30 minutes. A matching enabled environment-specific or `*` maker approval excludes the sequence. One result per publication selects the latest qualifying creation. Inventory is **left-joined**, never used to exclude a new/rogue agent: `RegistrationStatus` is `Registered` for an enabled inventory match and `Unknown` otherwise. The output AgentId is the observed BotId. An empty inventory watchlist is valid for this rule; the watchlist itself must still exist.

`BotId` is extracted only from `Properties.BotId` or `PropertyCollection.BotId`. **Validate actual tenant payloads before enablement**: array-shaped collections, differently named/nested properties and missing IDs are intentionally skipped, not guessed. Newly created agents need not be preregistered; an observed real BotId is sufficient for event linkage. No placeholder watchlist row can manufacture the required native creation and publication records. A different creator/publisher, actor object ID without a UPN, missing environment/UID or delayed event outside the lookback produces no match. Exact event linkage and rapid publishing are governance review signals, not malicious intent.

### agent-authentication-change

Requires `PowerPlatformAdminActivity` and inventory. Successful `BotUpdateOperation-BotAuthUpdate` with validated BotId and event UID yields one configuration result per audit event. It does **not** say authentication was disabled or weakened: the operation name is insufficient to compare old/new mode. Resolve old/new settings from independently validated payload details or the control plane during investigation. ActorUPN is populated only for a UPN-valued ActorName. The same payload caveats as creation/publication apply.

### agent-permission-audit

Requires `AuditLogs` and inventory with nonempty `ServicePrincipalObjectId`. Deduplicates successful audit records by `Id`, expands `TargetResources`, and selects `ServicePrincipal` targets with an exact known object ID. Monitors `Add app role assignment to service principal` and `Add delegated permission grant`. Validate operation spellings and the target type/ID payload against actual tenant audit events before enablement.

This is a **permission configuration review** analytic, not a risky-scope classifier or privilege-escalation detector. TargetResources can include client and resource principals; an inventory match does not establish which role the principal played, that it received a grant, or that the permission is risky. Evidence explicitly records an unresolved target role. Review modified properties and the original event to determine grantee, resource, role/scope, initiator and expected change ticket. No unverified modified-property names are parsed.

### agent-permission-then-signin

Requires the preceding audit prerequisites plus `AADServicePrincipalSignInLogs`. Joins a known targeted SP object ID to successful (`ResultType=0`) `ServicePrincipalId` within 30 minutes after the audit; deduplicates source IDs and returns the latest preceding audit per sign-in. ActorUPN is the **audit initiator**, not the service principal. IP entity is the sign-in source address.

The sign-in establishes authentication, not API/data access, use of the newly audited permission, sensitive-data access or escalation. Target-role ambiguity remains. Service-principal sign-in aggregation/delivery delays can lose or repeat a sequence. The separate configuration rule remains useful where service-principal sign-ins are unavailable; do not replace unavailable evidence with fabricated access events.

### runtime-shell-network

Requires `DeviceProcessEvents`, `DeviceNetworkEvents`, enabled inventory and runtime registrations. A direct child `ProcessCreated` event must name one of powershell.exe, pwsh.exe, cmd.exe, wscript.exe, cscript.exe, mshta.exe, bash.exe or sh.exe and match the registered parent DeviceId/filename/path. A `ConnectionSuccess` must follow within ten minutes from that exact child's **DeviceId + ProcessId + ProcessCreationTime**, using network `InitiatingProcessId` and `InitiatingProcessCreationTime`. The creation-time equality is essential protection against PID reuse. One result selects the first qualifying connection per child event.

This is a selected-shell behavior analytic, not a learned unusual-child baseline. Legitimate administration/build tools can trigger. Indirect descendants, other executables, runtimes without endpoint coverage and missing creation timestamps are not covered. Shell execution supports an Execution tactic mapping; a network connection alone proves neither command-and-control nor exfiltration. Process command lines are deliberately not copied into evidence.

### runtime-new-destination

Requires `DeviceNetworkEvents`, inventory, runtime inventory and a valid enabled destination policy for each agent. Matches successful direct runtime connections and parses hostnames from native `RemoteUrl`, normalizing case and trailing dots. Excludes missing URLs, IP-only hosts, malformed hosts and approved exact hostnames. A recent (one-hour) destination is new only if absent from observations earlier than that hour within the 14-day query period.

Cold-start guard requires observations on at least **three distinct baseline days** for that agent. It deliberately suppresses new/quiet runtimes, but three days do not prove complete coverage; retention, outages and runtime inventory changes still affect novelty. Baseline is per agent across registered devices. This is hostname novelty and policy review, not first-ever contact, payload inspection, arbitrary MDE file-read visibility or data-theft evidence. DNS/CDN changes and ordinary new services may trigger. IP-only events are not silently treated as hostname evidence.

## Optional normalized custom-event rules

These rules are not deployable prerequisites for native coverage. Only deploy them after creating and populating **`AIAgentEvent_CL`** with the following exact typed schema, using a supported ingestion API/DCR appropriate to the workspace. A table name alone does not establish producer trust. Do not enable them against legacy `_s` column suffixes or invented native AI tables.

| Column | Type / allowed values |
|---|---|
| TimeGenerated | datetime; producer event time, not replay time |
| EventId | string; nonempty immutable event ID, unique within AgentId |
| AgentId | string; registered canonical agent ID |
| SessionId | string; nonempty session ID unique within agent, never reused across unrelated sessions |
| EventType | string: InjectionSignal / ToolInvocation / DataAccess / ExternalSubmission / Heartbeat |
| ActorUPN | string; real user UPN if meaningful, otherwise empty |
| ToolName | string; required for the external-tool submission rule |
| DestinationHost | string; canonical DNS/punycode host, no URL, port or wildcard |
| DataClassification | string: Public / Internal / Confidential / HighlyConfidential |
| Outcome | string: Succeeded / Blocked / Failed / Unknown |
| ResourceId | string; opaque/redacted resource identifier, not contents |
| CorrelationId | string; shared trace context, nonempty for the sensitive-data sequence |
| Evidence | string; redacted summary only; queries do not forward this producer-controlled text |
| SchemaVersion | string; `1.0` for this release |

Producers must authenticate, validate classification provenance, preserve event IDs/timestamps across retries, synchronize clocks, prevent session reuse, and redact raw prompts/secrets/data. Events are deduplicated by AgentId + EventId before sequence matching; only supported schema version participates. Replayed immutable duplicates do not add matches within an evaluation. Corrections/reused IDs are outside the contract.

### injection-signal-then-action

Requires the custom table and enabled inventory. An `InjectionSignal` must precede a `ToolInvocation` or `ExternalSubmission` with `Outcome=Succeeded`, same agent and session, strictly positive elapsed time and at most ten minutes. Equal timestamps do not establish order. One result chooses the latest preceding signal per action. A blocked signal can coexist with later legitimate activity: this rule intentionally reports **association**, not successful prompt influence. Blocked, failed and unknown actions never count as consequences. A detector signal and a session join do not prove that the action was malicious.

### sensitive-data-then-external-tool

Requires the custom table, inventory and per-agent allowed destinations. A successful `DataAccess` of `Confidential` or `HighlyConfidential` classification must strictly precede a successful `ExternalSubmission` by at most ten minutes, sharing agent, session and **nonempty CorrelationId**. Submission must name a tool and valid non-allowlisted exact destination host. One result selects the latest preceding read per submission. Missing policies, labels, trace IDs or tool names suppress the match rather than manufacture evidence. Matching context does not prove that submitted bytes contain the previously read information; verify with authorized, redacted application telemetry. Generic tool invocation without an explicit submission event is insufficient.

## Scheduling, health and validation

One-hour windows overlap every 15 minutes: source-event deduplication is within a query evaluation, **not persistent cross-run suppression**. Configure incident grouping/suppression appropriate to the tenant and use evidence event IDs for triage deduplication. Late arrivals outside the query period, clock skew and events straddling its boundaries can be missed. The 14-day rule scans more data and costs more; validate retention and query performance before enabling. `queryFrequency` never exceeds one day and `queryPeriod` never exceeds 14 days.

No rule alerts naively because a table has no rows. Quiet agents, missing tables, expired retention, disconnected connectors and broken ingestion need distinct operational handling. Use health hunts/workbook coverage views and expected-source onboarding state to compare last-seen timestamps, baselines, watchlist readiness and connector status. Missing data is not evidence of evasion. Do not replace this health workflow with an unqualified no-data scheduled threat alert.

Run `python -B -m unittest discover -s tests -p test_detections.py -v` for dependency-free catalog/static checks and a fixture-based reference oracle covering ordering, allowlists, enabled/known inventory, deduplication, successful consequences and PID reuse. **These tests do not execute or compile KQL.** Before enablement, run each full query with `| take 0` against the target workspace to validate tables, columns, watchlists and KQL syntax, then run controlled positive/negative telemetry and inspect results, ingestion latency and cost. Query compilation alone does not validate operation payloads or business meaning. No cloud validation or deployment was performed by these offline tests.

## Microsoft schema references

Reviewed against public Microsoft Learn references; operation payload shapes still require tenant validation:

- [PowerPlatformAdminActivity](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/powerplatformadminactivity): TimeGenerated, EventOriginalType, EventOriginalUid, ActorName, ActorUserId, EventResult, Properties, PropertyCollection, EnvironmentId, Workload.
- [Power Platform activity logs](https://learn.microsoft.com/en-us/power-platform/admin/activity-logging-auditing/activity-logs-overview).
- [AuditLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs): InitiatedBy, TargetResources, OperationName, Result, Id.
- [AADServicePrincipalSignInLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs): ServicePrincipalId, ResultType, Id, IPAddress, ResourceDisplayName.
- [DeviceProcessEvents](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/deviceprocessevents) and [DeviceNetworkEvents](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/devicenetworkevents): Sentinel ingestion TimeGenerated plus documented native process/network fields. These are the Azure Monitor schemas, not an assumption that Defender advanced hunting's Timestamp field exists here.
