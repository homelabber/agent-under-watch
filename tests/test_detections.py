"""Offline contract checks and reference fixtures; these do not compile/execute KQL."""
import json
import re
import unittest
import uuid
from pathlib import Path, PureWindowsPath

ROOT = Path(__file__).resolve().parents[1]
KNOWN = {"agent-a"}


def norm(value):
    return str(value).lower()


def duration_seconds(value):
    match = re.fullmatch(r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?", value)
    if not match or not any(match.groups()):
        raise ValueError(value)
    days, hours, minutes, seconds = (int(part or 0) for part in match.groups())
    return days * 86400 + hours * 3600 + minutes * 60 + seconds


def sequences(events, sensitive=False, allowed=None, known=None):
    """Reference oracle: fixture times are event-time minutes, IDs immutable."""
    known = KNOWN if known is None else known
    dedup = {}
    for event in events:
        agent = norm(event.get("agent", ""))
        if agent not in known or not event.get("id") or not event.get("session"):
            continue
        if event.get("schema", "1.0") != "1.0":
            continue
        key = (agent, event["id"])
        if key not in dedup or event["time"] > dedup[key]["time"]:
            dedup[key] = dict(event, agent=agent)
    output = set()
    for action in dedup.values():
        if action.get("outcome") != "Succeeded":
            continue
        if sensitive:
            if action["type"] != "ExternalSubmission" or not action.get("tool") or not action.get("trace"):
                continue
            hosts = (allowed or {}).get(action["agent"], set())
            host = norm(action.get("host", "")).rstrip(".")
            if not hosts or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host):
                continue
            if host in {norm(item).rstrip(".") for item in hosts}:
                continue
        elif action["type"] not in {"ToolInvocation", "ExternalSubmission"}:
            continue
        for signal in dedup.values():
            expected = "DataAccess" if sensitive else "InjectionSignal"
            if signal["type"] != expected or signal["agent"] != action["agent"]:
                continue
            if signal["session"] != action["session"] or signal["id"] == action["id"]:
                continue
            if not 0 < action["time"] - signal["time"] <= 10:
                continue
            if sensitive and (signal.get("outcome") != "Succeeded"
                              or signal.get("classification") not in {"Confidential", "HighlyConfidential"}
                              or signal.get("trace") != action["trace"]):
                continue
            output.add(action["id"])
    return output


def rapid_publish(created, published, approvals):
    agent, actor, environment = (norm(created[field]) for field in ("agent", "actor", "environment"))
    if not agent or "@" not in actor or not environment:
        return False
    if any(norm(published[field]) != norm(created[field]) for field in ("agent", "actor", "environment")):
        return False
    if created["result"] != "Succeeded" or published["result"] != "Succeeded":
        return False
    if not 0 <= published["time"] - created["time"] <= 30:
        return False
    return not any(norm(row["enabled"]) == "true" and norm(row["actor"]) == actor
                   and norm(row["environment"]) in {environment, "*"} for row in approvals)


def child_network_match(child, network):
    return (norm(child["device"]) == norm(network["device"])
            and child["pid"] == network["pid"]
            and child.get("created") is not None
            and child["created"] == network.get("created")
            and network["outcome"] == "ConnectionSuccess"
            and 0 <= network["time"] - child["time"] <= 10)


def novel_destination(host, baseline, allowlist):
    """Baseline fixtures use (observed_day, host), not raw KQL execution."""
    host = norm(host).rstrip(".")
    return (bool(allowlist) and len({day for day, _ in baseline}) >= 3
            and host not in {norm(value).rstrip(".") for _, value in baseline}
            and host not in {norm(value).rstrip(".") for value in allowlist})


class CatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = json.loads((ROOT / "catalog" / "rules.json").read_text(encoding="utf-8"))

    def test_shape_and_stable_identity(self):
        self.assertIsInstance(self.rules, list)
        self.assertEqual(len(self.rules), 8)
        self.assertEqual(sum(not rule["optional"] for rule in self.rules), 6)
        self.assertEqual(sum(rule["optional"] for rule in self.rules), 2)
        for field in ("id", "key", "queryFile"):
            self.assertEqual(len({rule[field] for rule in self.rules}), len(self.rules))
        for rule in self.rules:
            self.assertEqual(str(uuid.UUID(rule["id"])), rule["id"])
            self.assertRegex(rule["key"], r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

    def test_deployment_contract(self):
        required = {"id", "key", "name", "description", "severity", "queryFile", "queryFrequency",
                    "queryPeriod", "triggerOperator", "triggerThreshold", "tactics", "enabled",
                    "optional", "requiredTables", "requiredWatchlists", "correlation", "limitations"}
        tactics = {"Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution", "Persistence",
                   "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess", "Discovery",
                   "LateralMovement", "Collection", "CommandAndControl", "Exfiltration", "Impact"}
        for rule in self.rules:
            with self.subTest(rule=rule["key"]):
                self.assertTrue(required <= rule.keys())
                self.assertIs(rule["enabled"], False)
                self.assertIsInstance(rule["optional"], bool)
                self.assertEqual(rule["triggerOperator"], "GreaterThan")
                self.assertEqual(rule["triggerThreshold"], 0)
                self.assertIn(rule["severity"], {"High", "Medium", "Low", "Informational"})
                self.assertIn(rule["correlation"], {"exact", "heuristic", "configuration"})
                self.assertTrue(set(rule["tactics"]) <= tactics)
                frequency = duration_seconds(rule["queryFrequency"])
                period = duration_seconds(rule["queryPeriod"])
                self.assertTrue(0 < frequency <= 86400)
                self.assertTrue(frequency <= period <= 14 * 86400)
                self.assertTrue(rule["limitations"])

    def test_queries_and_declared_dependencies(self):
        tables = {"PowerPlatformAdminActivity", "AuditLogs", "AADServicePrincipalSignInLogs",
                  "DeviceProcessEvents", "DeviceNetworkEvents", "AIAgentEvent_CL"}
        paths = set()
        for rule in self.rules:
            with self.subTest(rule=rule["key"]):
                relative = PureWindowsPath(rule["queryFile"])
                self.assertFalse(relative.is_absolute())
                self.assertNotIn("..", relative.parts)
                self.assertEqual(relative.parts[:2], ("kql", "analytics"))
                self.assertIn("\\", rule["queryFile"])
                path = ROOT.joinpath(*relative.parts)
                paths.add(path)
                query = path.read_text(encoding="utf-8")
                self.assertEqual(set(re.findall(r"_GetWatchlist\('([^']+)'\)", query)),
                                 set(rule["requiredWatchlists"]))
                used_tables = {table for table in tables if re.search(r"\b" + table + r"\b", query)}
                self.assertEqual(used_tables, set(rule["requiredTables"]))
                self.assertIn("AIAgentInventory", rule["requiredWatchlists"])
                for column in ("TimeGenerated", "AgentId", "ActorUPN", "Evidence", "CorrelationQuality"):
                    self.assertIn(column, query.rsplit("| project", 1)[-1])
                self.assertIn("tolower(tostring(Enabled)) == 'true'", query)
                self.assertNotIn("OfficeActivity", query)
                self.assertNotIn("datatable(", query)
                self.assertNotIn("union isfuzzy", query)
                self.assertEqual("AIAgentEvent_CL" in used_tables, rule["optional"])
        self.assertEqual(paths, set((ROOT / "kql" / "analytics").glob("*.kql")))

    def test_native_linkage_and_cold_start_guards(self):
        queries = {rule["key"]: ROOT.joinpath(*PureWindowsPath(rule["queryFile"]).parts).read_text(encoding="utf-8")
                   for rule in self.rules}
        self.assertIn("on DeviceId, ChildPid, ChildCreated", queries["runtime-shell-network"])
        self.assertIn("ChildCreated = InitiatingProcessCreationTime", queries["runtime-shell-network"])
        self.assertIn("ObservedDays >= 3", queries["runtime-new-destination"])
        self.assertIn("join kind=inner BaselineReady", queries["runtime-new-destination"])
        for key in ("runtime-new-destination", "sensitive-data-then-external-tool"):
            self.assertIn("join kind=inner ConfiguredAgents", queries[key])
        self.assertIn("by AgentId, EventId", queries["injection-signal-then-action"])
        self.assertIn("on AgentId, SessionId, CorrelationId", queries["sensitive-data-then-external-tool"])
        self.assertIn("SignInAt >= GrantAt and SignInAt <= GrantAt + 30m", queries["agent-permission-then-signin"])
        self.assertIn("join kind=leftouter Agents on AgentId", queries["rapid-unapproved-publish"])
        self.assertIn("RegistrationStatus", queries["rapid-unapproved-publish"].rsplit("| project", 1)[-1])
        for key, query in queries.items():
            if key != "rapid-unapproved-publish":
                self.assertIn("join kind=inner Agents on", query)


class SequenceFixtureTests(unittest.TestCase):
    def setUp(self):
        self.signal = dict(agent="AGENT-A", id="signal-1", session="s1", time=1, type="InjectionSignal")
        self.action = dict(agent="agent-a", id="action-1", session="s1", time=5,
                           type="ToolInvocation", outcome="Succeeded")
        self.read = dict(agent="agent-a", id="read-1", session="s1", time=1, type="DataAccess",
                         outcome="Succeeded", classification="Confidential", trace="trace-1")
        self.send = dict(agent="agent-a", id="send-1", session="s1", time=5, type="ExternalSubmission",
                         outcome="Succeeded", host="Other.Example.", tool="web", trace="trace-1")
        self.policy = {"agent-a": {"approved.example"}}

    def test_signal_success_and_replay_dedup(self):
        self.assertEqual(sequences([self.signal, self.action] * 3), {"action-1"})

    def test_no_success_from_blocked_failed_unknown(self):
        for outcome in ("Blocked", "Failed", "Unknown"):
            with self.subTest(outcome=outcome):
                self.assertFalse(sequences([self.signal, dict(self.action, outcome=outcome)]))
                self.assertFalse(sequences([self.read, dict(self.send, outcome=outcome)], True, self.policy))

    def test_strict_order_and_bounded_time(self):
        for time in (0, 1, 12):
            self.assertFalse(sequences([self.signal, dict(self.action, time=time)]))
        self.assertEqual(sequences([self.signal, dict(self.action, time=11)]), {"action-1"})

    def test_agent_session_schema_and_id_guard(self):
        for changes in ({"agent": "unknown"}, {"session": "s2"}, {"session": ""},
                        {"id": ""}, {"schema": "2.0"}):
            self.assertFalse(sequences([self.signal, dict(self.action, **changes)]))
        self.assertFalse(sequences([self.signal, self.action], known=set()))

    def test_sensitive_sequence_and_trace_guard(self):
        self.assertEqual(sequences([self.read, self.send] * 2, True, self.policy), {"send-1"})
        for changes in ({"trace": "other"}, {"trace": ""}, {"tool": ""}, {"type": "ToolInvocation"},
                        {"host": "https://other.example"}, {"host": "*.example"}, {"session": "s2"}):
            self.assertFalse(sequences([self.read, dict(self.send, **changes)], True, self.policy))

    def test_sensitive_classification_and_success_required(self):
        for changes in ({"classification": "Public"}, {"classification": "Internal"},
                        {"outcome": "Blocked"}, {"outcome": "Failed"}, {"trace": ""}):
            self.assertFalse(sequences([dict(self.read, **changes), self.send], True, self.policy))

    def test_sensitive_policy_empty_and_exact_host_approval(self):
        for allowed in (None, {}, {"agent-a": set()}, {"agent-a": {"OTHER.EXAMPLE."}}):
            self.assertFalse(sequences([self.read, self.send], True, allowed))
        # Parent domain approval does not approve a subdomain.
        self.assertEqual(sequences([self.read, dict(self.send, host="sub.approved.example")], True, self.policy), {"send-1"})


class NativeFixtureTests(unittest.TestCase):
    def setUp(self):
        self.created = dict(agent="AGENT-A", actor="Maker@Example.org", environment="env-a", time=0, result="Succeeded")
        self.published = dict(self.created, time=20)

    def test_maker_scope_case_and_enabled_guards(self):
        self.assertTrue(rapid_publish(self.created, self.published, []))
        for environment in ("ENV-A", "*"):
            approval = dict(actor="maker@example.org", environment=environment, enabled="TRUE")
            self.assertFalse(rapid_publish(self.created, self.published, [approval]))
            self.assertTrue(rapid_publish(self.created, self.published, [dict(approval, enabled="false")]))
        other = dict(actor="maker@example.org", environment="env-b", enabled="true")
        self.assertTrue(rapid_publish(self.created, self.published, [other]))

    def test_publish_same_actor_environment_and_window(self):
        for changes in ({"time": -1}, {"time": 31}, {"actor": "other@example.org"},
                        {"environment": "env-b"}, {"result": "PartiallySucceeded"}, {"agent": "unknown"}):
            self.assertFalse(rapid_publish(self.created, dict(self.published, **changes), []))
        self.assertFalse(rapid_publish(dict(self.created, agent=''), dict(self.published, agent=''), []))

    def test_unregistered_new_agent_is_detected_without_inventory(self):
        created = dict(self.created, agent='new-unregistered-bot')
        published = dict(self.published, agent='NEW-UNREGISTERED-BOT')
        self.assertTrue(rapid_publish(created, published, []))
        approval = dict(actor='maker@example.org', environment='*', enabled='true')
        self.assertFalse(rapid_publish(created, published, [approval]))

    def test_child_pid_reuse_and_device_guards(self):
        child = dict(device="DEVICE-A", pid=42, created=100, time=2)
        network = dict(device="device-a", pid=42, created=100, time=5, outcome="ConnectionSuccess")
        self.assertTrue(child_network_match(child, network))
        for changes in ({"created": 200}, {"device": "device-b"}, {"pid": 43},
                        {"outcome": "ConnectionFailed"}, {"time": 1}, {"time": 13}, {"created": None}):
            self.assertFalse(child_network_match(child, dict(network, **changes)))
        self.assertFalse(child_network_match(dict(child, created=None), network))

    def test_novel_destination_policy_baseline_and_cold_start(self):
        baseline = [(1, "old.example"), (2, "old.example"), (3, "old.example")]
        self.assertTrue(novel_destination("new.example", baseline, {"approved.example"}))
        self.assertFalse(novel_destination("OLD.EXAMPLE.", baseline, {"approved.example"}))
        self.assertFalse(novel_destination("APPROVED.EXAMPLE.", baseline, {"approved.example"}))
        self.assertFalse(novel_destination("new.example", baseline, set()))
        self.assertFalse(novel_destination("new.example", baseline[:2], {"approved.example"}))
        self.assertFalse(novel_destination("new.example", [(1, "old.example")] * 3, {"approved.example"}))


if __name__ == "__main__":
    unittest.main()
