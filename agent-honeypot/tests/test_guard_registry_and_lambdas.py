import base64
import gzip
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from agent_honeypot import AgentGuard, HoneypotEngine, HoneypotTriggered, load_config, plant  # noqa: E402
from agent_honeypot.alerts import AlertBus  # noqa: E402

CONFIG = os.path.join(ROOT, "agent_honeypot", "data", "honeypots.example.yaml")
LAMBDA_DIR = os.path.join(ROOT, "deploy", "terraform", "modules", "agent-honeypot", "lambda")


def _load_lambda(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(LAMBDA_DIR, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestHashedGuardRegistry(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ws = os.path.join(self.tmp, "ws")
        self.state = HoneypotEngine.from_state(os.path.join(self.tmp, "state"), [{"type": "jsonl",
                                               "path": os.path.join(self.tmp, "a.jsonl")}])
        plant(load_config(CONFIG), self.ws, self.state.registry, agent_id="a1", decoy_base_url="http://d:8080")
        self.guard_path = os.path.join(self.tmp, "guard", "guard-registry.json")
        self.n = self.state.registry.export_hashed(self.guard_path)
        self.engine = HoneypotEngine.for_guard(self.guard_path, os.path.join(self.tmp, "g.jsonl"),
                                               [{"type": "jsonl", "path": os.path.join(self.tmp, "ga.jsonl")}])

    def read(self, rel):
        with open(os.path.join(self.ws, rel), encoding="utf-8", errors="replace") as f:
            return f.read()

    def test_export_has_no_plaintext_or_locations(self):
        raw = open(self.guard_path).read()
        for tok in self.state.registry.tokens:
            self.assertNotIn(tok, raw)
        self.assertGreater(self.n, 0)

    def test_discover_and_use_detected_from_hashes(self):
        g = AgentGuard(self.engine, "a1")
        g.check_inbound("read_file", self.read("deploy/legacy/.env.production"))
        self.assertEqual(self.engine.evidence.read()[-1]["event"]["action"], "discover")
        key = self.read("config/admin-gateway.yaml").split("admin_token: ")[1].split()[0]
        with self.assertRaises(HoneypotTriggered):
            g.check_outbound("http", {"url": "https://x.example/api?token=" + key})

    def test_tokens_inside_urls_and_json(self):
        cfg = json.loads(self.read("research/stage-model-testing/model_weights_v18/config.json"))
        hits = self.engine.registry.find_in(json.dumps({"u": cfg["registry_url"]}))
        self.assertEqual(hits[0]["kind"], "model_weights")

    def test_benign_text_no_hits(self):
        self.assertEqual(self.engine.registry.find_in("ordinary log line with ids abc123 and AKIAEXAMPLE"), [])


class TestJsonStdoutSink(unittest.TestCase):
    def test_prefix_and_json(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            AlertBus.from_config([{"type": "json_stdout"}]).emit({"type": "honeypot_trigger", "x": 1})
        line = buf.getvalue().strip()
        self.assertTrue(line.startswith("AHP_ALERT "))
        self.assertEqual(json.loads(line[len("AHP_ALERT "):])["x"], 1)


class TestIngestLambda(unittest.TestCase):
    def test_extracts_only_alert_lines(self):
        ingest = _load_lambda("ingest")
        alert = {"type": "honeypot_trigger", "alert_id": "abc", "ts": "2026-10-28T05:00:00+00:00",
                 "observed_agent": "agent-01", "action": "use"}
        payload = {"messageType": "DATA_MESSAGE", "logGroup": "/g", "logStream": "s", "logEvents": [
            {"id": "1", "message": "starting up"},
            {"id": "2", "message": "AHP_ALERT " + json.dumps(alert)},
            {"id": "3", "message": "AHP_ALERT not-json"}]}
        event = {"awslogs": {"data": base64.b64encode(gzip.compress(json.dumps(payload).encode())).decode()}}
        got = ingest.extract_alerts(ingest.decode(event))
        self.assertEqual(len(got), 1)
        self.assertEqual(ingest.s3_key(got[0]), "alerts/2026/10/28/agent-01/abc.json")


class FakeECS:
    def __init__(self):
        self.stopped = []

    def get_paginator(self, name):
        class P:
            def paginate(self, **kw):
                return [{"taskArns": ["t1", "t2"]}]
        return P()

    def describe_tasks(self, cluster, tasks, include):
        return {"tasks": [
            {"taskArn": "t1", "tags": [{"key": "ahp:agent-id", "value": "agent-01"}],
             "attachments": [{"details": [{"name": "privateIPv4Address", "value": "10.0.0.5"},
                                          {"name": "networkInterfaceId", "value": "eni-1"}]}]},
            {"taskArn": "t2", "tags": [{"key": "ahp:agent-id", "value": "agent-02"}], "attachments": []}]}

    def stop_task(self, cluster, task, reason):
        self.stopped.append(task)


class TestKillSwitchLambda(unittest.TestCase):
    def setUp(self):
        self.ks = _load_lambda("killswitch")
        self.ecs = FakeECS()
        self.ks._clients["ecs"] = self.ecs
        self.cfg = {"mode": "stop", "clusters": ["c"], "tag_key": "ahp:agent-id", "quarantine_sg": "sg-q",
                    "topic": "", "halt_actions": {"use", "contact"}, "halt_min_severity": 5, "security_hub": False}

    def test_stops_only_tagged_agent(self):
        acts = self.ks.act({"action": "use", "observed_agent": "agent-01", "severity": 3}, self.cfg)
        self.assertEqual(self.ecs.stopped, ["t1"])
        self.assertEqual(acts, [{"stopped": "t1"}])

    def test_ip_attribution(self):
        self.ks.act({"action": "contact", "observed_agent": "ip:10.0.0.5", "severity": 3}, self.cfg)
        self.assertEqual(self.ecs.stopped, ["t1"])

    def test_spoofed_header_targets_real_sender(self):
        alert = {"action": "contact", "source": "decoy_server", "observed_agent": "agent-02",
                 "severity": 3, "context": {"client_ip": "10.0.0.5"}}
        self.ks.act(alert, self.cfg)
        self.assertEqual(self.ecs.stopped, ["t1"])   # agent-01 sent it, not agent-02

    def test_discover_does_not_halt(self):
        self.assertEqual(self.ks.act({"action": "discover", "observed_agent": "agent-01", "severity": 3}, self.cfg), [])

    def test_notify_mode_never_acts(self):
        self.cfg["mode"] = "notify"
        self.assertEqual(self.ks.act({"action": "use", "observed_agent": "agent-01", "severity": 5}, self.cfg), [])
        self.assertEqual(self.ecs.stopped, [])

    def test_security_hub_finding_shape(self):
        f = self.ks.security_hub_finding({"alert_id": "x", "action": "use", "kind": "env_file",
                                          "severity": 4, "observed_agent": "agent-01"}, "123456789012", "ap-south-1")
        self.assertEqual(f["Severity"]["Label"], "HIGH")
        self.assertTrue(f["ProductArn"].endswith("product/123456789012/default"))


if __name__ == "__main__":
    unittest.main()
