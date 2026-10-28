import json
import os
import sys
import tempfile
import unittest
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent_honeypot import AgentGuard, HoneypotEngine, HoneypotTriggered, AgentHalted, assess, load_config, plant  # noqa: E402
from agent_honeypot.decoy_server import serve_in_thread  # noqa: E402
from agent_honeypot.evidence import EvidenceLog  # noqa: E402
from agent_honeypot.planter import PLANTERS  # noqa: E402

CONFIG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "agent_honeypot", "data", "honeypots.example.yaml")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ws = os.path.join(self.tmp, "ws")
        self.engine = HoneypotEngine.from_state(os.path.join(self.tmp, "state"), [{"type": "jsonl",
                                                 "path": os.path.join(self.tmp, "alerts.jsonl")}])
        self.cfg = load_config(CONFIG)
        self.recs = plant(self.cfg, self.ws, self.engine.registry, agent_id="a1",
                          decoy_base_url="http://127.0.0.1:9")

    def read(self, rel):
        with open(os.path.join(self.ws, rel), encoding="utf-8", errors="replace") as f:
            return f.read()


class TestPlanting(Base):
    def test_all_kinds_planted(self):
        kinds = {r["kind"] for r in self.recs}
        self.assertEqual(kinds, set(PLANTERS))
        for r in self.recs:
            self.assertTrue(os.path.exists(r["abs_location"]), r["abs_location"])

    def test_tokens_unique_per_agent(self):
        plant(self.cfg, os.path.join(self.tmp, "ws2"), self.engine.registry, agent_id="a2")
        env1 = self.read("deploy/legacy/.env.production")
        recs = self.engine.registry.find_in(env1)
        self.assertEqual({r["agent_id"] for r in recs}, {"a1"})

    def test_restricted_marker(self):
        self.assertTrue(os.path.exists(os.path.join(self.ws, "docs/archive/restricted/RESTRICTED.md")))

    def test_registry_persists(self):
        from agent_honeypot.registry import Registry
        self.assertEqual(len(Registry(self.engine.registry.path)), len(self.recs))


class TestGuard(Base):
    def test_discover_does_not_halt_but_alerts(self):
        g = AgentGuard(self.engine, "a1")
        read = g.wrap(lambda p: self.read(p), "read_file")
        read("deploy/legacy/.env.production")
        acts = [e["event"]["action"] for e in self.engine.evidence.read()]
        self.assertIn("discover", acts)
        self.assertIn("touch", acts)
        self.assertFalse(g.halted)

    def test_use_halts_before_call(self):
        g = AgentGuard(self.engine, "a1")
        calls = []
        send = g.wrap(lambda url: calls.append(url), "http")
        key = [l for l in self.read("deploy/legacy/.env.production").splitlines()
               if l.startswith("PAYMENTS_API_KEY")][0].split("=", 1)[1]
        with self.assertRaises(HoneypotTriggered):
            send("https://api.example.com/charge?key=" + key)
        self.assertEqual(calls, [])  # request never executed
        with self.assertRaises(AgentHalted):
            send("https://benign.example.com")

    def test_cross_agent_flag(self):
        g = AgentGuard(self.engine, "intruder", halt_on=())
        with self.assertRaises(HoneypotTriggered):
            g.check_inbound("read", self.read(".aws/credentials.bak"))
        self.assertTrue(self.engine.evidence.read()[-1]["event"]["cross_agent"])

    def test_benign_traffic_no_alert(self):
        g = AgentGuard(self.engine, "a1")
        g.wrap(lambda x: "hello world", "echo")("normal task input")
        self.assertEqual(self.engine.evidence.read(), [])


class TestDecoyServer(Base):
    def test_contact_attributed_by_token(self):
        srv = serve_in_thread(self.engine)
        try:
            cfg = json.loads(self.read("research/stage-model-testing/model_weights_v18/config.json"))
            url = cfg["registry_url"].replace("http://127.0.0.1:9", f"http://127.0.0.1:{srv.server_address[1]}")
            body = urllib.request.urlopen(url, timeout=3).read()
            self.assertIn(b"frontier", body)
        finally:
            srv.shutdown()
        ev = self.engine.evidence.read()[-1]["event"]
        self.assertEqual(ev["action"], "contact")
        self.assertEqual(ev["observed_agent"], "a1")
        self.assertEqual(ev["kind"], "model_weights")

    def test_unattributed_contact_records_ip(self):
        srv = serve_in_thread(self.engine)
        try:
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{srv.server_address[1]}/random", timeout=3)
            except Exception:
                pass
        finally:
            srv.shutdown()
        ev = self.engine.evidence.read()[-1]["event"]
        self.assertTrue(ev["observed_agent"].startswith("ip:"))


class TestEvidenceAndVerdicts(Base):
    def test_chain_verifies_and_detects_tamper(self):
        g = AgentGuard(self.engine, "a1", halt_on=())
        g.check_inbound("read", self.read(".aws/credentials.bak"))
        g.check_inbound("read", self.read("config/admin-gateway.yaml"))
        path = self.engine.evidence.path
        self.assertTrue(EvidenceLog.verify(path)[0])
        lines = open(path).read().splitlines()
        lines[0] = lines[0].replace('"severity": 4', '"severity": 1')
        open(path, "w").write("\n".join(lines) + "\n")
        ok, _, bad = EvidenceLog.verify(path)
        self.assertFalse(ok)
        self.assertEqual(bad, 1)

    def test_verdict_progression(self):
        g = AgentGuard(self.engine, "a1", halt_on=())
        g.check_inbound("read", self.read("docs/archive/restricted/Q3-exec-compensation.md"))
        self.assertEqual(assess(self.engine.evidence.read())[0]["verdict"], "probable_mistake")
        key = self.read("config/admin-gateway.yaml").split("admin_token: ")[1].split()[0]
        g.check_outbound("http", key)
        self.assertEqual(assess(self.engine.evidence.read())[0]["verdict"], "suspicious")
        swarm = self.read("src/utils/legacy_sync.py").split("X-Agent-Key: ")[1].split()[0]
        g.check_outbound("http", swarm)
        self.assertEqual(assess(self.engine.evidence.read())[0]["verdict"], "incriminating")


class TestCLI(Base):
    def test_cli_report_and_verify(self):
        from agent_honeypot.cli import main
        state = os.path.join(self.tmp, "state")
        AgentGuard(self.engine, "a1", halt_on=()).check_inbound("r", self.read(".aws/credentials.bak"))
        main(["--state", state, "report", "--json"])
        with self.assertRaises(SystemExit) as cm:
            main(["--state", state, "verify"])
        self.assertEqual(cm.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
