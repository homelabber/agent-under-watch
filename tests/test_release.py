"""Offline packaging checks. These do not execute KQL or call Azure."""
from __future__ import annotations

import csv
import importlib.util
import json
from pathlib import Path
import re
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("build_content", ROOT / "tools" / "build_content.py")
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


def load(relative: str):
    return json.loads((ROOT / relative).read_text(encoding="utf-8-sig"))


def duration_seconds(text: str) -> int:
    match = re.fullmatch(r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?", text)
    if not match:
        raise ValueError(text)
    days, hours, minutes, seconds = (int(value or 0) for value in match.groups())
    return days * 86400 + hours * 3600 + minutes * 60 + seconds


class ReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = load("catalog/rules.json")

    def test_catalog_has_native_and_explicit_optional_rules(self):
        self.assertGreaterEqual(len([r for r in self.rules if not r["optional"]]), 6)
        self.assertGreaterEqual(len([r for r in self.rules if r["optional"]]), 2)
        self.assertEqual(len({r["key"] for r in self.rules}), len(self.rules))
        self.assertEqual(len({r["id"] for r in self.rules}), len(self.rules))
        for rule in self.rules:
            with self.subTest(rule=rule["key"]):
                uuid.UUID(rule["id"])
                self.assertFalse(rule["enabled"])
                self.assertTrue(rule["requiredTables"])
                self.assertTrue(rule["limitations"])
                self.assertIn(rule["severity"], {"High", "Medium", "Low", "Informational"})
                self.assertGreater(duration_seconds(rule["queryFrequency"]), 0)
                self.assertLessEqual(duration_seconds(rule["queryFrequency"]), duration_seconds(rule["queryPeriod"]))
                self.assertLessEqual(duration_seconds(rule["queryPeriod"]), 14 * 86400)
                if not rule["optional"]:
                    self.assertNotIn("AIAgentEvent_CL", rule["requiredTables"])

    def test_rule_templates_exactly_embed_source_queries(self):
        for rule in self.rules:
            with self.subTest(rule=rule["key"]):
                arm = load("arm/rules/" + rule["key"] + ".json")
                source = ROOT / Path(rule["queryFile"].replace("\\", "/"))
                props = arm["resources"][0]["properties"]
                self.assertEqual(props["query"], source.read_text(encoding="utf-8-sig"))
                self.assertFalse(arm["parameters"]["enableRule"]["defaultValue"])
                self.assertEqual(props["enabled"], "[parameters('enableRule')]")
                self.assertEqual(props["customDetails"]["AgentId"], "AgentId")
                self.assertEqual(props["customDetails"]["CorrelationQuality"], "CorrelationQuality")
                for key in ("severity", "queryPeriod", "queryFrequency", "triggerThreshold", "triggerOperator", "tactics"):
                    self.assertEqual(props[key], rule[key])
                for alias in re.findall(r"_GetWatchlist\(['\"]([^'\"]+)", props["query"]):
                    self.assertIn(alias, BUILD.WATCHLISTS)
                    self.assertIn(alias, rule["requiredWatchlists"])

    def test_watchlist_templates_have_disabled_seeds_and_exact_contract(self):
        for alias, columns in BUILD.WATCHLISTS.items():
            with self.subTest(alias=alias):
                with (ROOT / "watchlists" / (alias + ".csv")).open(encoding="utf-8-sig", newline="") as stream:
                    reader = csv.DictReader(stream)
                    rows = list(reader)
                    self.assertEqual(reader.fieldnames, columns)
                    self.assertTrue(rows)
                    self.assertTrue(all(row["Enabled"] in {"true", "false"} for row in rows))
                    self.assertTrue(all(row["Enabled"] == "false" for row in rows if row["SearchKey"] == "disabled-seed"))

    def test_workbook_has_honest_health_and_workspace_scope(self):
        wb = load("workbooks/ai-agent-threats.workbook.json")
        self.assertEqual(wb, BUILD.workbook())
        self.assertEqual(wb["version"], "Notebook/1.0")
        queries = [item["content"] for item in wb["items"] if item["type"] == 3]
        self.assertGreaterEqual(len(queries), 7)
        for content in queries:
            self.assertEqual(content["crossComponentResources"], ["{Workspace}"])
            self.assertEqual(content["timeContextFromParameter"], "TimeRange")
        health = next(q for q in queries if q["title"] == "Source availability and last seen")
        self.assertIn("datatable(Source:string", health["query"])
        self.assertIn("NOT OBSERVED", health["query"])
        self.assertIn("does not prove complete coverage", health["query"])
        self.assertIn("isfuzzy=true", health["query"])

    def test_workbook_has_alert_trend_and_incident_views(self):
        wb = load("workbooks/ai-agent-threats.workbook.json")
        queries = {item["content"]["title"]: item["content"] for item in wb["items"] if item["type"] == 3}
        self.assertTrue(any(q["visualization"] == "tiles" for q in queries.values()))
        self.assertTrue(any(q["visualization"] == "timechart" for q in queries.values()))
        incidents = queries["Incident triage queue"]["query"]
        self.assertIn("SecurityIncident", incidents)
        self.assertIn("arg_max(TimeGenerated, *) by IncidentNumber", incidents)
        coverage = queries["Detection prerequisites and evidence boundaries"]["query"]
        for rule in self.rules:
            self.assertIn(rule["name"], coverage)

    def test_deployment_inventory_guard_allows_creation_only(self):
        script = (ROOT / "scripts" / "deploy.ps1").read_text(encoding="utf-8-sig")
        self.assertIn("$knownAgentRules = @($selected | Where-Object { $_.key -ne 'rapid-unapproved-publish' })", script)
        self.assertIn("if ($knownAgentRules.Count -and -not $watchlists.AIAgentInventory.Count)", script)
        self.assertNotIn("Replace the disabled inventory seed with at least one enabled real agent before uploading watchlists.", script)

    def test_workbook_arm_escaping_and_binding(self):
        arm = load("arm/workbook.json")
        expression = arm["resources"][0]["properties"]["serializedData"]
        expected_wb = json.dumps(BUILD.workbook(), separators=(",", ":")).replace("'", "''")
        self.assertEqual(expression, "[replace('" + expected_wb + "', '__WORKSPACE_RESOURCE_ID__', variables('workspaceResourceId'))]")
        self.assertEqual(arm["parameters"]["workbookName"]["defaultValue"], "[guid(resourceGroup().id, parameters('workspaceName'), 'ai-agent-threats-v1')]")

    def test_optional_table_stream_and_dcr_share_schema(self):
        arm = load("arm/optional-telemetry.json")
        table, endpoint, dcr = arm["resources"]
        self.assertEqual(table["properties"]["schema"]["name"], "AIAgentEvent_CL")
        columns = table["properties"]["schema"]["columns"]
        self.assertEqual({c["name"]: c["type"] for c in columns}, BUILD.EVENT_COLUMNS)
        self.assertEqual(columns, dcr["properties"]["streamDeclarations"]["Custom-AIAgentEvent"]["columns"])
        flow = dcr["properties"]["dataFlows"][0]
        self.assertEqual(flow["outputStream"], "Custom-AIAgentEvent_CL")
        self.assertEqual(flow["transformKql"], "source")
        self.assertEqual(endpoint["properties"]["networkAcls"]["publicNetworkAccess"], "Enabled")
        self.assertEqual(len(dcr["dependsOn"]), 2)

    def test_threat_sources_distinguish_research_and_observed_activity(self):
        threats = load("catalog/threats.json")
        self.assertGreaterEqual(len(threats), 3)
        self.assertTrue(any("Research" in source["classification"] for source in threats))
        self.assertTrue(any("Observed malicious" in source["classification"] for source in threats))
        for source in threats:
            self.assertTrue(source["url"].startswith("https://"))
            self.assertTrue(source["coverage"])
            self.assertTrue(source["actorAttribution"])

    def test_preview_is_offline_and_not_fake_live_data(self):
        page = (ROOT / "preview" / "index.html").read_text(encoding="utf-8")
        self.assertIn("no tenant connection and no live metrics", page)
        self.assertNotRegex(page, r"(?i)<script|<iframe|<img[^>]+src=[\"']https?://")
        self.assertEqual(page.count('<article>'), len(self.rules))
        self.assertIn("Not connected", page)

    def test_every_json_is_valid_and_arm_has_resource_contract(self):
        for path in ROOT.rglob("*.json"):
            with self.subTest(path=str(path.relative_to(ROOT))):
                value = json.loads(path.read_text(encoding="utf-8-sig"))
                if "arm" in path.relative_to(ROOT).parts:
                    self.assertTrue(value["$schema"].startswith("https://schema.management.azure.com/"))
                    self.assertTrue(value["resources"])
                    for resource in value["resources"]:
                        self.assertTrue(resource["apiVersion"])
                        self.assertTrue(resource["name"])


if __name__ == "__main__":
    unittest.main()
