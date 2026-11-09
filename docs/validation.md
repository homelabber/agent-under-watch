# Validation and production acceptance

## Offline checks

Release verification: **27 tests passed**, repeated artifact generation produced **no file-content changes**, and the PowerShell helper parsed without syntax errors. These are offline results only.

Run `python -B tools\build_content.py`, then `python -B -m unittest discover -s tests -v`.

The dependency-free suites cover:

- Catalog IDs, scheduling bounds, explicit dependencies, native/optional separation, disabled defaults and output-column contracts.
- Generated ARM queries exactly matching the readable KQL source.
- Watchlist headers and inactive seed behavior.
- Workbook workspace/time scoping, telemetry-health wording and embedded ARM string escaping.
- Custom-table/DCR stream schema consistency and explicit endpoint networking settings.
- Offline preview content and absence of external scripts or fabricated live metrics.
- Reference fixtures for successful versus blocked actions, session isolation, event deduplication, bounded ordering, classification and destination policy checks.
- Native reference fixtures for unregistered creation/publication, maker approvals, PID reuse and destination-baseline cold starts.

Reference fixtures are Python models of intended behavior; **they are not execution of KQL** and cannot establish semantic equivalence with the Kusto engine. JSON checks are structural; they do not establish Azure resource-provider acceptance.

PowerShell parser validation checks syntax only. On the development device, running the unsigned deployment helper was blocked by signing policy. No policy was changed. Its runtime paths, including `-ValidateOnly` and `-WhatIf`, therefore remain unverified here and require an approved signed copy before execution on devices with that requirement.

## Limited tenant compatibility check

On 2026-11-09, all six native queries compiled successfully against a test workspace's actual native source tables. Each `_GetWatchlist(...)` call was replaced with an empty in-query datatable matching the documented watchlist schema, and `| take 0` was appended. No source event records were returned and no resources were deployed.

This confirms resolution of the substituted queries against those source-table schemas. It does **not** validate actual watchlists, scheduled rule behavior, detection outcomes, optional custom telemetry, workbook rendering, ARM deployment or production readiness. Synthetic KQL behavioral tests and controlled end-to-end scenarios have not been run. Tenant-specific identities, event counts, reports and credentials are deliberately excluded from public content.

## Tenant acceptance gate

Before enabling any rule:

1. Review Azure resource-provider/API support, licenses, preview status and region availability. Validate ARM templates against the target subscription using approved deployment procedures.
2. Deploy and validate customer watchlists. Check exact IDs and runtime paths; ensure no enabled seed/sample identity is present. A shared service principal/runtime cannot be attributed to a single agent by assumption.
3. Verify each required table and actual column/payload shape. Check Copilot Studio BotId extraction and Entra target-role interpretation specifically.
4. Compile each full query against the target workspace. Appending `| take 0` validates resolution without returning event content; it does not test detection outcomes. The helper does this before deploying selected rules once allowed to execute.
5. Run controlled positive and negative telemetry in a test environment with synthetic data. Inspect real query results, not only a successful API response. Confirm blocked actions do not count as successful consequences.
6. Test unknown agents in the creation/publication scenario, disabled inventory rows, approved makers in correct/wrong environments, and agent identities sharing display names but not IDs.
7. Test endpoint PID reuse and registered executable paths. Establish at least three observed historical days before expecting destination-novelty results. Verify ordinary administration does not create unacceptable noise.
8. For optional events, test schema/version rejection, unique sessions, immutable IDs, trusted classifications, empty policy guards, exact destination matching and successful/failed/blocked distinctions. Confirm the producer cannot submit raw secrets or forged source classifications.
9. Measure ingestion delay, query latency/cost, retention, overlapping-run duplicates and false positives. Configure appropriate incident grouping only after verifying stable shared evidence.
10. Check workbook queries, alert/incident visibility, sensitive-evidence access and tenant RBAC with actual analyst roles. No tenant-connected visual validation was performed here.

## Rebuilding

The builder overwrites generated ARM, workbook and preview files deterministically. Existing watchlist CSVs are intentionally preserved. Regenerate after changing catalog/KQL/workbook source; rerun tests. Review disabled defaults and rule identity stability before applying updates. An organization-applied signature on a changed PowerShell helper must be renewed through the approved signing process.

## What is not claimed

No live Azure deployment, authenticated KQL compilation, production alert-fidelity result, connector completeness, zero-day coverage, automatic native-to-custom telemetry conversion or successful containment is claimed by this release's offline tests.
