"""Build deterministic Azure deployment artifacts and an offline demonstration."""
from __future__ import annotations

import csv
import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.0.0"
WATCHLISTS = {
    "AIAgentInventory": ["SearchKey", "AgentId", "AgentName", "ServicePrincipalObjectId", "AppId", "OwnerUPN", "Criticality", "Enabled"],
    "AIAgentApprovedMakers": ["SearchKey", "ActorUPN", "EnvironmentId", "Enabled"],
    "AIAgentRuntimeInventory": ["SearchKey", "RuntimeKey", "AgentId", "DeviceId", "ProcessFileName", "ProcessFolderPath", "Enabled"],
    "AIAgentAllowedDestinations": ["SearchKey", "AgentId", "DestinationHost", "Enabled"],
}
EVENT_COLUMNS = {
    "TimeGenerated": "datetime", "EventId": "string", "AgentId": "string",
    "SessionId": "string", "EventType": "string", "ActorUPN": "string",
    "ToolName": "string", "DestinationHost": "string", "DataClassification": "string",
    "Outcome": "string", "ResourceId": "string", "CorrelationId": "string",
    "Evidence": "string", "SchemaVersion": "string",
}


def write(path: str, text: str) -> None:
    target = ROOT / Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8", newline="\n")


def write_json(path: str, value: object) -> None:
    write(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def template(parameters: dict, resources: list, variables: dict | None = None) -> dict:
    result = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0", "parameters": parameters, "resources": resources,
    }
    if variables:
        result["variables"] = variables
    return result


def text_item(title: str, body: str) -> dict:
    return {"type": 1, "name": title, "content": {"json": f"## {title}\n\n{body}"}}


def query_item(title: str, query: str, visualization: str = "table") -> dict:
    return {
        "type": 3, "name": title,
        "content": {
            "version": "KqlItem/1.0", "title": title, "query": query,
            "size": 0, "queryType": 0,
            "resourceType": "microsoft.operationalinsights/workspaces",
            "crossComponentResources": ["{Workspace}"],
            "visualization": visualization,
            "timeContextFromParameter": "TimeRange",
        },
    }


def workbook() -> dict:
    inventory = "_GetWatchlist('AIAgentInventory') | where tolower(tostring(Enabled)) == 'true'"
    health = '''let Expected = datatable(Source:string) ["PowerPlatformAdminActivity", "AuditLogs", "AADServicePrincipalSignInLogs", "DeviceProcessEvents", "DeviceNetworkEvents", "SecurityAlert", "AIAgentEvent_CL"];
let Seen = union isfuzzy=true
    (datatable(Source:string, LastSeen:datetime) []),
    (PowerPlatformAdminActivity | summarize LastSeen=max(TimeGenerated) | extend Source="PowerPlatformAdminActivity"),
    (AuditLogs | summarize LastSeen=max(TimeGenerated) | extend Source="AuditLogs"),
    (AADServicePrincipalSignInLogs | summarize LastSeen=max(TimeGenerated) | extend Source="AADServicePrincipalSignInLogs"),
    (DeviceProcessEvents | summarize LastSeen=max(TimeGenerated) | extend Source="DeviceProcessEvents"),
    (DeviceNetworkEvents | summarize LastSeen=max(TimeGenerated) | extend Source="DeviceNetworkEvents"),
    (SecurityAlert | summarize LastSeen=max(TimeGenerated) | extend Source="SecurityAlert"),
    (AIAgentEvent_CL | summarize LastSeen=max(TimeGenerated) | extend Source="AIAgentEvent_CL");
Expected | join kind=leftouter Seen on Source
| extend Status=case(isnull(LastSeen), "NOT OBSERVED — missing, empty, or outside selected window", LastSeen < ago(2h), "STALE — investigate expected cadence", "RECEIVING — does not prove complete coverage")
| project Source, LastSeen, Status'''
    items = [
        text_item("Agent Under Watch — PREVIEW", "**Preview: not production-validated. Investigation and correlation, not a zero-day guarantee.** Native-first deployment; optional normalized agent events are separately enabled. All analytics deploy disabled. A missing signal is not a clean bill of health."),
        {"type": 9, "name": "Scope", "content": {"version": "KqlParameterItem/1.0", "style": "pills", "parameters": [
            {"id": "workspace", "name": "Workspace", "type": 5, "isRequired": True, "value": "__WORKSPACE_RESOURCE_ID__", "typeSettings": {"resourceTypeFilter": {"microsoft.operationalinsights/workspaces": True}, "additionalResourceOptions": []}},
            {"id": "time", "name": "TimeRange", "type": 4, "isRequired": True, "value": {"durationMs": 86400000}, "typeSettings": {"selectableValues": [{"durationMs": 3600000}, {"durationMs": 86400000}, {"durationMs": 604800000}]}}
        ]}},
        text_item("SOC overview", "Start with pack-generated alerts, then pivot by AgentId and entity evidence. Configuration findings are not confirmed compromise. Related events linked only by time must remain explicitly heuristic."),
        query_item("Alert volume by severity", '''SecurityAlert
| where AlertName startswith "AI Agent |"
| summarize Alerts=dcount(SystemAlertId) by AlertSeverity''', "tiles"),
        query_item("Alert trend", '''SecurityAlert
| where AlertName startswith "AI Agent |"
| summarize Alerts=dcount(SystemAlertId) by bin(TimeGenerated, 1h), AlertSeverity
| order by TimeGenerated asc''', "timechart"),
        query_item("Pack alerts", '''SecurityAlert
| where AlertName startswith "AI Agent |"
| summarize Alerts=dcount(SystemAlertId), LastSeen=max(TimeGenerated) by AlertName, AlertSeverity
| order by LastSeen desc'''),
        query_item("Incident triage queue", '''SecurityIncident
| where Title startswith "AI Agent |"
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| project IncidentNumber, Title, Severity, Status, AssignedTo=tostring(Owner.assignedTo), IncidentUrl, LastModifiedTime
| order by LastModifiedTime desc'''),
        query_item("Known agent ownership and exposure", inventory + "\n| project AgentId, AgentName, OwnerUPN, Criticality, ServicePrincipalObjectId, AppId"),
        text_item("Lifecycle and trust", "Creation, publication, authentication changes and component changes. Verify the actual change before calling it a weakening. BotId extraction requires tenant payload validation; unresolved IDs are a coverage gap."),
        query_item("Agent authoring timeline", '''PowerPlatformAdminActivity
| where EventOriginalType startswith "Bot" or EventOriginalType startswith "AIPlugin"
| extend AgentId=coalesce(tostring(Properties.BotId), tostring(PropertyCollection.BotId))
| project TimeGenerated, AgentId, ActorName, EventOriginalType, EventResult, EnvironmentId, EventOriginalUid
| order by TimeGenerated desc'''),
        text_item("Identity and access", "Only explicitly inventoried agent identities are in scope. These sign-ins do not by themselves prove which agent session caused a resource operation. Successful sign-in is not proof of sensitive-data access."),
        query_item("Known agent service principal sign-ins", '''let Agents=_GetWatchlist('AIAgentInventory')
| where tolower(tostring(Enabled)) == "true"
| project AgentId=tolower(tostring(AgentId)), SPId=tolower(tostring(ServicePrincipalObjectId));
AADServicePrincipalSignInLogs
| extend SPId=tolower(ServicePrincipalId)
| join kind=inner Agents on SPId
| project TimeGenerated, AgentId, ServicePrincipalId, IPAddress, ResourceDisplayName, ResultType, CorrelationId
| order by TimeGenerated desc'''),
        text_item("Prompt injection and data exposure — optional", "Requires the normalized AIAgentEvent_CL contract, validated producer identity and stable agent/session IDs. Native alerts remain in Defender. No claim is made that standard audit events contain full prompts, tool arguments or sensitive-content labels."),
        query_item("Optional agent session timeline", '''union isfuzzy=true
(datatable(TimeGenerated:datetime, AgentId:string, SessionId:string, EventType:string, ToolName:string, DestinationHost:string, Outcome:string, Evidence:string) []),
(AIAgentEvent_CL | project TimeGenerated, AgentId, SessionId, EventType, ToolName, DestinationHost, Outcome, Evidence)
| order by TimeGenerated desc | take 200'''),
        text_item("Endpoint execution", "Map exact DeviceId, runtime executable and folder path before enabling endpoint rules. Child process and network evidence establish process lineage, not prompt causality. Device timelines may contain sensitive command lines; use native protected investigation views."),
        query_item("Registered runtime activity", '''let Runtimes=_GetWatchlist('AIAgentRuntimeInventory')
| where tolower(tostring(Enabled)) == "true"
| project AgentId=tostring(AgentId), DeviceId=tostring(DeviceId), RuntimeName=tolower(tostring(ProcessFileName)), RuntimeFolder=tolower(tostring(ProcessFolderPath));
DeviceProcessEvents
| extend RuntimeName=tolower(InitiatingProcessFileName), RuntimeFolder=tolower(InitiatingProcessFolderPath)
| join kind=inner Runtimes on DeviceId, RuntimeName, RuntimeFolder
| project TimeGenerated, AgentId, DeviceName, FileName, FolderPath, InitiatingProcessFileName, ProcessId, InitiatingProcessId
| order by TimeGenerated desc | take 200'''),
        text_item("Threat-informed coverage", "Sources and evidence classifications live in catalog/threats.json. Techniques are not attributed to an actor without evidence. Detections must be replay-tested and tuned against your tenant. Last six months is a maintenance priority, not a reason to discard older techniques."),
        text_item("Telemetry health", "NOT OBSERVED combines missing table, no records, and selected-window limitations. It is never labeled healthy. The two-hour stale indicator is an investigation prompt, not an outage detector; adapt to source cadence. Optional tables are not core prerequisites."),
        query_item("Source availability and last seen", health),
        query_item("Optional schema and producer coverage", '''union isfuzzy=true
(datatable(TimeGenerated:datetime, AgentId:string, SchemaVersion:string, EventType:string) []),
(AIAgentEvent_CL | project TimeGenerated, AgentId, SchemaVersion, EventType)
| summarize LastSeen=max(TimeGenerated), Events=count(), EventTypes=make_set(EventType, 20) by AgentId, SchemaVersion'''),
    ]
    rules_path = ROOT / "catalog" / "rules.json"
    rules = json.loads(rules_path.read_text(encoding="utf-8-sig")) if rules_path.exists() else []
    rows = []
    for rule in rules:
        rows.extend([rule["name"], "Optional" if rule["optional"] else "Native", rule["correlation"], ", ".join(rule["requiredTables"]), rule["limitations"]])
    coverage = "datatable(Detection:string, Module:string, Correlation:string, RequiredTables:string, Limitations:string) [\n" + ",\n".join(json.dumps(value) for value in rows) + "\n]"
    position = next(index for index, item in enumerate(items) if item["name"] == "Threat-informed coverage")
    items.insert(position + 1, query_item("Detection prerequisites and evidence boundaries", coverage))
    return {"version": "Notebook/1.0", "items": items, "isLocked": False, "fallbackResourceIds": ["__WORKSPACE_RESOURCE_ID__"]}


def build() -> None:
    wb = workbook()
    write_json("workbooks/ai-agent-threats.workbook.json", wb)
    serialized = json.dumps(wb, separators=(",", ":")).replace("'", "''")
    params = {"workspaceName": {"type": "string"}, "location": {"type": "string"}, "workbookName": {"type": "string", "defaultValue": "[guid(resourceGroup().id, parameters('workspaceName'), 'ai-agent-threats-v1')]"}}
    write_json("arm/workbook.json", template(params, [{
        "type": "Microsoft.Insights/workbooks", "apiVersion": "2022-04-01", "name": "[parameters('workbookName')]", "location": "[parameters('location')]", "kind": "shared",
        "properties": {"displayName": "Agent Under Watch — PREVIEW", "category": "sentinel", "sourceId": "[variables('workspaceResourceId')]", "version": "1.0", "serializedData": "[replace('" + serialized + "', '__WORKSPACE_RESOURCE_ID__', variables('workspaceResourceId'))]"}
    }], {"workspaceResourceId": "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspaceName'))]"}))
    write_json("arm/watchlist.json", template({"workspaceName": {"type": "string"}, "alias": {"type": "string", "allowedValues": list(WATCHLISTS)}, "rawContent": {"type": "string"}}, [{
        "type": "Microsoft.OperationalInsights/workspaces/providers/watchlists", "apiVersion": "2024-03-01", "name": "[format('{0}/Microsoft.SecurityInsights/{1}', parameters('workspaceName'), parameters('alias'))]",
        "properties": {"displayName": "[parameters('alias')]", "watchlistAlias": "[parameters('alias')]", "provider": "Agent Under Watch (Preview)", "source": "Local file", "sourceType": "Local file", "description": "Customer maintained agent trust boundary. Disabled seed entries never authorize activity.", "itemsSearchKey": "SearchKey", "contentType": "text/csv", "numberOfLinesToSkip": 0, "rawContent": "[parameters('rawContent')]"}
    }]))
    for alias, columns in WATCHLISTS.items():
        path = ROOT / "watchlists" / (alias + ".csv")
        # Never overwrite customer-maintained inventories on rebuild.
        if not path.exists():
            row = {column: "" for column in columns}
            row.update({"SearchKey": "disabled-seed", "Enabled": "false"})
            if "AgentId" in row:
                row["AgentId"] = "disabled-seed"
            import io
            stream = io.StringIO(newline="")
            writer = csv.DictWriter(stream, fieldnames=columns, lineterminator="\n")
            writer.writeheader()
            writer.writerow(row)
            write("watchlists/" + alias + ".csv", stream.getvalue())
    catalog_path = ROOT / "catalog" / "rules.json"
    rules = json.loads(catalog_path.read_text(encoding="utf-8-sig")) if catalog_path.exists() else []
    for rule in rules:
        query = (ROOT / Path(rule["queryFile"].replace("\\", "/"))).read_text(encoding="utf-8-sig")
        properties = {key: rule[key] for key in ["description", "severity", "queryFrequency", "queryPeriod", "triggerOperator", "triggerThreshold", "tactics"]}
        properties.update({"displayName": "AI Agent | " + rule["name"], "query": query, "enabled": "[parameters('enableRule')]", "suppressionDuration": "PT1H", "suppressionEnabled": False, "incidentConfiguration": {"createIncident": True, "groupingConfiguration": {"enabled": False}}, "eventGroupingSettings": {"aggregationKind": "SingleAlert"}, "customDetails": {"AgentId": "AgentId", "CorrelationQuality": "CorrelationQuality"}})
        write_json("arm/rules/" + rule["key"] + ".json", template({"workspaceName": {"type": "string"}, "enableRule": {"type": "bool", "defaultValue": False}}, [{"type": "Microsoft.OperationalInsights/workspaces/providers/alertRules", "apiVersion": "2024-03-01", "kind": "Scheduled", "name": "[format('{0}/Microsoft.SecurityInsights/" + rule["id"] + "', parameters('workspaceName'))]", "properties": properties}]))
    columns = [{"name": name, "type": kind} for name, kind in EVENT_COLUMNS.items()]
    table_id = "[resourceId('Microsoft.OperationalInsights/workspaces/tables', parameters('workspaceName'), 'AIAgentEvent_CL')]"
    write_json("arm/optional-telemetry.json", template({"workspaceName": {"type": "string"}, "location": {"type": "string"}, "dceName": {"type": "string", "defaultValue": "[format('ai-agent-{0}', uniqueString(resourceGroup().id, parameters('workspaceName')))]"}, "dcrName": {"type": "string", "defaultValue": "[format('ai-agent-{0}', uniqueString(resourceGroup().id, parameters('workspaceName')))]"}}, [
        {"type": "Microsoft.OperationalInsights/workspaces/tables", "apiVersion": "2022-10-01", "name": "[format('{0}/AIAgentEvent_CL', parameters('workspaceName'))]", "properties": {"schema": {"name": "AIAgentEvent_CL", "columns": columns}, "retentionInDays": 30, "totalRetentionInDays": 30}},
        {"type": "Microsoft.Insights/dataCollectionEndpoints", "apiVersion": "2022-06-01", "name": "[parameters('dceName')]", "location": "[parameters('location')]", "properties": {"networkAcls": {"publicNetworkAccess": "Enabled"}}},
        {"type": "Microsoft.Insights/dataCollectionRules", "apiVersion": "2022-06-01", "name": "[parameters('dcrName')]", "location": "[parameters('location')]", "dependsOn": [table_id, "[resourceId('Microsoft.Insights/dataCollectionEndpoints', parameters('dceName'))]"], "properties": {"dataCollectionEndpointId": "[resourceId('Microsoft.Insights/dataCollectionEndpoints', parameters('dceName'))]", "streamDeclarations": {"Custom-AIAgentEvent": {"columns": columns}}, "destinations": {"logAnalytics": [{"name": "agentWorkspace", "workspaceResourceId": "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspaceName'))]"}]}, "dataFlows": [{"streams": ["Custom-AIAgentEvent"], "destinations": ["agentWorkspace"], "transformKql": "source", "outputStream": "Custom-AIAgentEvent_CL"}]}}
    ]))
    build_preview(rules)


def build_preview(rules: list) -> None:
    cards = "".join(f'<article><span class="badge">{"OPTIONAL" if r["optional"] else "NATIVE"}</span><h3>{html.escape(r["name"])}</h3><p>{html.escape(r["description"])}</p><small>{html.escape(r["severity"])} · {html.escape(r["correlation"])} · disabled by default</small></article>' for r in rules)
    document = '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Agent Under Watch — PREVIEW</title><style>
:root{color-scheme:dark;font-family:Segoe UI,Arial,sans-serif;background:#0c1424;color:#e7edf8}body{max-width:1220px;margin:auto;padding:36px}h1{font-size:36px;margin-bottom:12px}h2{margin-top:36px}p{line-height:1.65;color:#b8c6dc}.eyebrow,.badge{color:#55ddc7;font-size:12px;letter-spacing:1px}.notice{border-left:4px solid #efbc68;background:#1e2637;padding:16px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:18px}article{background:#152139;border:1px solid #2d405d;border-radius:10px;padding:22px}small{color:#a5b6d2}nav{display:flex;flex-wrap:wrap;gap:10px;margin:25px 0}nav a{color:#d1e5ff;text-decoration:none;padding:9px 13px;border:1px solid #3c5273;border-radius:20px}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:12px;border-bottom:1px solid #304058}.status{color:#efbc68}footer{margin-top:30px;color:#9aabc5}a{color:#7dcdf6}</style></head><body>
<div class="eyebrow">SENTINEL CONTENT PACK · PREVIEW · NOT PRODUCTION-VALIDATED</div><h1>Agent Under Watch</h1><p>Your agents have tools. Your SOC should have questions. Correlate agent lifecycle, identities and endpoint activity. Investigate evidence—not just usage.</p><div class="notice"><strong>Offline release preview — no tenant connection and no live metrics.</strong> This page describes the packaged workbook and rules. It is not a simulation of real findings. All analytics deploy disabled; optional agent events require a separately configured producer.</div>
<nav><a href="#rules">Detection coverage</a><a href="#health">Telemetry health</a><a href="#deploy">Deployment</a></nav><h2 id="rules">Packaged analytics</h2><section class="grid">''' + cards + '''</section><h2 id="health">Visibility before confidence</h2><table><thead><tr><th>Source</th><th>Offline status</th><th>Purpose</th></tr></thead><tbody><tr><td>Power Platform audit</td><td class="status">Not connected</td><td>Agent creation and changes</td></tr><tr><td>Entra audit and workload sign-ins</td><td class="status">Not connected</td><td>Known agent identities and permissions</td></tr><tr><td>Defender endpoint events</td><td class="status">Not connected</td><td>Registered runtime process lineage</td></tr><tr><td>Optional normalized agent events</td><td class="status">Not configured</td><td>Session-level injection and data-exposure correlations</td></tr></tbody></table><h2 id="deploy">Safe deployment path</h2><p>Read README.md → validate native connectors and watchlists → deploy the workbook → deploy selected rules disabled → review evidence and false positives → explicitly enable reviewed rules.</p><footer>No promise of zero-day detection. See docs for source provenance, correlation limitations, privacy and response guidance.</footer></body></html>'''
    write("preview/index.html", document)


if __name__ == "__main__":
    build()
