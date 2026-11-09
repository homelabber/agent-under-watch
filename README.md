# Agent Under Watch

### Your agents have tools. Your SOC should have questions.

**AI-agent threat analytics for Microsoft Sentinel — PREVIEW**

Agent Under Watch is a native-first Sentinel content pack for investigating AI-agent lifecycle, identity and endpoint activity. It connects the dots between who created an agent, what changed around its identity, and what a registered runtime did next. Because “the agent did it” is the beginning of an investigation, not the conclusion.

The first release includes a Sentinel workbook, **six native analytics**, **two optional custom-event correlations**, customer-maintained trust watchlists, ARM templates and investigation guidance. No mandatory MCP proxy or runtime SDK. Existing Microsoft telemetry does the heavy lifting—where you have actually connected it.

> **PREVIEW — not production-validated.** This is detection and investigation content, not an inline protection engine, Microsoft-supported product, or guaranteed zero-day detector. All rules deploy **disabled**. Validate schemas, mappings, query behavior, cost and false positives in your own tenant before enabling anything. Use at your own risk; no warranty of detection, availability or fitness for a particular purpose is provided. The pack does not replace native Microsoft security controls.

Configuration findings and temporal correlations are not proof of malicious intent. No cloud resources are created by building or testing this repository.

## What's under watch?

| Signal | What the pack looks for | What it does not prove |
|---|---|---|
| Agent authoring | Rapid creation and publication by an unapproved maker, including unregistered agents | That a new agent is malicious |
| Authentication configuration | Changes affecting registered agents | That authentication was weakened |
| Identity permissions | Permission audits targeting a known agent identity, optionally followed by sign-in | That a new permission was used or data was accessed |
| Runtime execution | A registered endpoint runtime spawning a shell that makes a network connection | That every shell is hostile |
| Network destinations | A new, non-allowlisted hostname after an observed baseline | That a connection exfiltrated data |
| Optional session evidence | Injection signal followed by successful action; sensitive access followed by external submission | Causation, prompt influence, or the exact bytes submitted |

**Trust, but query.** The pack favors explicit mappings, bounded correlations and visible limitations over theatrical certainty.

## Preview validation status

- **27 offline tests passed**, including packaging checks and Python reference fixtures. Those fixtures do not execute KQL.
- All **six native queries compiled against a test workspace's actual source tables**, with empty in-query watchlist schemas substituted and `take 0` appended. This is a limited compatibility check—not watchlist integration or detection validation.
- No Azure resources were deployed. ARM deployment, deployment-helper execution, synthetic KQL behavioral tests, controlled end-to-end activity and production false-positive rates remain unverified.
- Tenant reports, authentication caches and customer mappings are not distributed with this repository.

See [validation boundaries and the tenant acceptance checklist](docs/validation.md).

## Included

- Sentinel workbook: SOC overview, lifecycle, identity, optional agent session timeline, endpoint execution, threat coverage guidance and telemetry health.
- Native analytics for suspicious authoring, known agent identities and precisely registered endpoint runtimes. See [the rule catalog](catalog/rules.json) and [detection guide](docs/detections.md) for the actual rules and prerequisites.
- Four watchlist CSV templates with **disabled seeds only**, not fictional approved production agents.
- Per-rule ARM templates and a deployment helper with connector/query preflight, explicit enabling and `-WhatIf` support.
- Optional `AIAgentEvent_CL` table, data collection endpoint/rule, and session-based correlation rules. **No producer, MCP proxy or runtime SDK is installed.**
- An honest offline HTML preview: no live metrics or fabricated findings.
- Source provenance, offline tests, privacy and incident response guidance.

## Start here

1. Read [telemetry and architecture](docs/telemetry.md), then [rule limitations](docs/detections.md).
2. Validate connectors in the intended Sentinel workspace. A licensed Microsoft product does not mean the required logs are ingested.
3. Replace watchlist seeds with reviewed tenant mappings. Keep the documented column names. The builder never overwrites existing CSVs.
4. Build and run offline tests:

```powershell
python -B tools\build_content.py
python -B -m unittest discover -s tests -v
.\scripts\deploy.ps1 -ValidateOnly
```

Offline validation does **not** execute KQL, validate ARM against Azure, measure tenant false positives or test Microsoft platform behavior. Those require an authenticated tenant. The deployment helper performs server-side table, watchlist and full-query compilation checks before deploying rules.

## Deploy incrementally

Prerequisites: Azure CLI authenticated to the correct subscription; an existing Sentinel-enabled workspace; rights to create workbooks/watchlists/rules and query workspace logs. Optional telemetry additionally requires table/DCR/DCE permissions. No dependencies are installed automatically. Deployment prompts for confirmation. Use `-WhatIf` to inspect the component without contacting Azure.

**Windows signing requirement:** this development device blocks the unsigned PowerShell helper. Its syntax was parsed, but its execution modes could not be tested here. Have your organization review and sign it through the approved code-signing process before use where required. Do not weaken device policy or remove file protections. Python offline tests and artifact generation do not require running the helper.

```powershell
# Confirm your active subscription separately before applying anything.
az account show --query "{subscription:id,tenant:tenantId}" --output table

.\scripts\deploy.ps1 -ResourceGroup 'rg-security' -WorkspaceName 'law-security' -Component Workbook -WhatIf
.\scripts\deploy.ps1 -ResourceGroup 'rg-security' -WorkspaceName 'law-security' -Component Workbook

# Configure real CSV rows first. All four aliases are uploaded.
.\scripts\deploy.ps1 -ResourceGroup 'rg-security' -WorkspaceName 'law-security' -Component Watchlists

# List actual rule keys; choose only those with available sources.
Get-Content .\catalog\rules.json -Raw | ConvertFrom-Json | Select-Object key, optional, requiredTables

# Deploy core rules disabled; fails closed if any selected prerequisite is missing.
.\scripts\deploy.ps1 -ResourceGroup 'rg-security' -WorkspaceName 'law-security' -Component Rules

# Alternatively, select reviewed keys shown by the catalog.
# Add -RuleKey 'key-from-catalog' to the command above.

# After tenant replay, payload validation, thresholds and analyst review:
.\scripts\deploy.ps1 -ResourceGroup 'rg-security' -WorkspaceName 'law-security' -Component Rules -EnableRules -AcknowledgeTenantValidation
```

The helper compiles full queries with `take 0`; this validates schema and syntax, **not detection results**. Run each query normally in Logs before enabling. Deploy watchlists first and allow ingestion to complete. Deploying a rule again without `-EnableRules` disables it; review changes before redeployment. Run deployments from the workspace's resource group; cross-resource-group workspaces are not supported by these templates. The workbook is a shared Azure resource; use appropriate RBAC.

### Watchlists

| Alias | Purpose |
|---|---|
| `AIAgentInventory` | Explicit agent-to-identity mapping, ownership and criticality. Agent IDs are opaque strings; service principal object ID and app ID are distinct GUIDs. |
| `AIAgentApprovedMakers` | Approved maker UPN and environment. `*` allows that maker across environments; it is not a wildcard UPN. |
| `AIAgentRuntimeInventory` | Exact device ID, initiating executable name and full executable folder path. One process mapping per agent; shared indistinguishable runtimes cannot be safely attributed in v1. |
| `AIAgentAllowedDestinations` | Exact normalized destination hostname per agent; no scheme, port, path or wildcard. |

The rapid creation/publication rule includes observed unregistered agents; it uses inventory only for registration-status enrichment, so an inventory containing only its disabled seed is valid for that rule. Other rules require enabled real inventory. Empty approved-maker policy means no maker is approved: review it before enabling the publication rule.

**Keep customer mappings private.** The committed CSVs are generic templates. Copy them to a directory outside your clone and pass `-WatchlistDirectory 'C:\AgentUnderWatch-Private\watchlists'` when using the helper. Do not commit real agent inventories, user identities, device mappings, tokens or exported telemetry. `.gitignore` cannot protect edits to files already tracked by Git.

Set `Enabled` to `true` only for reviewed rows; use `false` to retain inactive entries. Enabled inventory AgentId values must be unique. This release rejects shared enabled app/service-principal mappings because it cannot distinguish agents behind the same identity. Never put credentials or prompt content in watchlists. Azure watchlists periodically refresh `TimeGenerated`; do not treat that as a configuration-change audit trail.

## Optional session correlations

See [the normalized telemetry contract](docs/telemetry.md#optional-normalized-agent-events). Deploy the table/DCE/DCR separately:

```powershell
.\scripts\deploy.ps1 -ResourceGroup 'rg-security' -WorkspaceName 'law-security' -Component OptionalTelemetry
# Configure an authenticated, least-privileged producer and verify events first.
.\scripts\deploy.ps1 -ResourceGroup 'rg-security' -WorkspaceName 'law-security' -Component OptionalRules
```

Native Defender agent telemetry is **not automatically converted** into this custom schema. Native alert names are not hard-coded as proof of prompt injection. Optional analytics require a trusted producer and supported source evidence. Do not enable them merely because the custom table exists.

## Preview

Open `preview\index.html` locally. It is generated from the rule catalog and intentionally has no backend, external scripts, network calls or tenant data. The real operational dashboard is `workbooks\ai-agent-threats.workbook.json` deployed through `arm\workbook.json`.

## Repository layout

- `kql\analytics`: readable queries; `catalog\rules.json`: deployment metadata and limitations.
- `arm\rules`: deterministic, disabled-by-default per-rule templates.
- `arm\workbook.json`, `arm\watchlist.json`, `arm\optional-telemetry.json`: supporting resources.
- `watchlists`: customer-maintained CSV inventories.
- `tools\build_content.py`: dependency-free artifact builder; run Python with `-B` to avoid cache files.
- `tests`: dependency-free offline validation; [validation boundaries](docs/validation.md).
- `catalog\threats.json`: dated reporting, evidence classifications and partial-coverage statements.
- `docs\response.md`: human-reviewed containment and evidence guidance.

## Scope boundaries

No automatic containment, MCP metadata collector, full transcript ingestion, secret scanning engine, local EDR deployment, connector provisioning or unrestricted discovery of every agent in the tenant. No production KQL/ARM validation is claimed without tenant testing. Native platform capabilities and preview availability vary by license, region and configuration. Threat-source links are research references, not endorsements or guarantees of campaign coverage.
