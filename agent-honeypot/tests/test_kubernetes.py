import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent_honeypot import HoneypotEngine, load_config, plant  # noqa: E402
from agent_honeypot.k8s import Responder  # noqa: E402
from agent_honeypot.tetragon import TetragonBridge, follow, parse_event  # noqa: E402

CONFIG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "agent_honeypot", "data", "honeypots.example.yaml")
POLICY = "agent-honeypot-decoys"


def tetra(path, agent="agent-01", fn="security_file_permission", mask=4, action="KPROBE_ACTION_POST",
          policy=POLICY, pod="agent-01-abc"):
    args = [{"file_arg": {"path": path}}]
    args.append({"uint_arg": 1} if fn == "security_mmap_file" else {"int_arg": mask})
    labels = {"agent-honeypot/agent-id": agent} if agent else {}
    return {"process_kprobe": {
        "process": {"pid": 42, "uid": 1000, "binary": "/usr/bin/cat", "arguments": path,
                    "pod": {"namespace": "ai-agents", "name": pod, "pod_labels": labels,
                            "container": {"name": "agent"}}},
        "function_name": fn, "args": args, "action": action, "policy_name": policy},
        "node_name": "node-1", "time": "2026-10-28T06:00:00Z"}


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class TestTetragonBridge(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.engine = HoneypotEngine.from_state(os.path.join(self.tmp, "state"),
                                                [{"type": "jsonl", "path": os.path.join(self.tmp, "a.jsonl")}])
        cfg = load_config(CONFIG)
        plant(cfg, os.path.join(self.tmp, "ws1"), self.engine.registry, "agent-01", "http://decoy")
        plant(cfg, os.path.join(self.tmp, "ws2"), self.engine.registry, "agent-02", "http://decoy")
        self.clock = Clock()
        self.b = TetragonBridge(self.engine, "/workspace", POLICY, clock=self.clock)

    def last(self):
        return self.engine.evidence.read()[-1]["event"]

    def test_parse(self):
        p = parse_event(tetra("/workspace/.aws/credentials.bak", mask=4))
        self.assertEqual((p["path"], p["access"], p["pod"]), ("/workspace/.aws/credentials.bak", "read", "agent-01-abc"))
        self.assertEqual(parse_event(tetra("/x", mask=2))["access"], "write")
        self.assertEqual(parse_event(tetra("/x", fn="security_mmap_file"))["access"], "mmap")
        self.assertIsNone(parse_event(tetra("/x", policy="other"), POLICY))
        self.assertIsNone(parse_event({"process_exec": {}}))

    def test_file_read_attributed(self):
        alerts = self.b.handle(tetra("/workspace/.aws/credentials.bak"))
        self.assertEqual(len(alerts), 1)
        ev = self.last()
        self.assertEqual((ev["action"], ev["source"], ev["observed_agent"], ev["kind"]),
                         ("touch", "tetragon", "agent-01", "cloud_credentials"))
        self.assertFalse(ev["cross_agent"])

    def test_directory_decoy_matches_children(self):
        self.b.handle(tetra("/workspace/research/stage-model-testing/model_weights_v18/model-00001-of-00004.safetensors",
                            fn="security_mmap_file"))
        self.assertEqual(self.last()["kind"], "model_weights")

    def test_dedupe_window(self):
        e = tetra("/workspace/deploy/legacy/.env.production")
        self.assertEqual(len(self.b.handle(e)), 1)
        self.assertEqual(self.b.handle(e), [])
        self.clock.t += 61
        self.assertEqual(len(self.b.handle(e)), 1)

    def test_enforced_never_deduped(self):
        e = tetra("/workspace/research/stage-model-testing/model_weights_v18/config.json", action="KPROBE_ACTION_SIGKILL")
        self.assertEqual(len(self.b.handle(e)), 1)
        self.assertEqual(len(self.b.handle(e)), 1)
        self.assertTrue(self.last()["context"]["enforced"])

    def test_other_paths_ignored(self):
        self.assertEqual(self.b.handle(tetra("/workspace/src/main.py")), [])
        self.assertEqual(self.b.handle(tetra("/etc/passwd")), [])

    def test_agent_label_selects_own_record(self):
        self.b.handle(tetra("/workspace/config/admin-gateway.yaml", agent="agent-02", pod="agent-02-x"))
        ev = self.last()
        self.assertEqual((ev["observed_agent"], ev["planted_for_agent"], ev["cross_agent"]), ("agent-02", "agent-02", False))

    def test_follow_survives_rotation(self):
        path = os.path.join(self.tmp, "tetragon.log")
        with open(path, "w") as f:
            f.write("a\n")
        g = follow(path, from_start=True, poll=0.01)
        self.assertEqual(next(g), "a\n")
        os.rename(path, path + ".1")
        with open(path, "w") as f:
            f.write("b\n")
        self.assertEqual(next(g), "b\n")


class FakeKube:
    def __init__(self):
        self.patches, self.deleted, self.queries = [], [], []
        self.pods = [
            {"metadata": {"name": "agent-01-abc", "labels": {"app": "agent-01", "pod-template-hash": "abc",
                                                             "agent-honeypot/agent-id": "agent-01"}},
             "status": {"phase": "Running", "podIP": "10.1.0.5"}},
            {"metadata": {"name": "agent-02-def", "labels": {"app": "agent-02", "agent-honeypot/agent-id": "agent-02"}},
             "status": {"phase": "Running", "podIP": "10.1.0.6"}},
        ]

    def list_pods(self, namespace, label_selector=None, field_selector=None):
        self.queries.append((label_selector, field_selector))
        out = self.pods
        if label_selector:
            k, v = label_selector.split("=", 1)
            out = [p for p in out if p["metadata"]["labels"].get(k) == v]
        if field_selector:
            k, v = field_selector.split("=", 1)
            key = {"status.podIP": ("status", "podIP"), "metadata.name": ("metadata", "name")}[k]
            out = [p for p in out if p[key[0]].get(key[1]) == v]
        return out

    def patch_pod_labels(self, namespace, name, labels):
        self.patches.append((name, labels))

    def delete_pod(self, namespace, name):
        self.deleted.append(name)


class TestResponder(unittest.TestCase):
    def setUp(self):
        self.kube = FakeKube()
        self.out = io.StringIO()
        self.r = Responder(self.kube, "ai-agents", out=self.out)

    def test_quarantine_strips_labels(self):
        acts = self.r.act({"alert_id": "a1", "action": "use", "observed_agent": "agent-01", "severity": 3})
        name, patch = self.kube.patches[0]
        self.assertEqual(name, "agent-01-abc")
        self.assertEqual(patch, {"app": None, "pod-template-hash": None, "agent-honeypot/quarantine": "true",
                                 "agent-honeypot/alert-id": "a1"})
        self.assertEqual(acts[0]["removed_labels"], ["app", "pod-template-hash"])

    def test_decoy_contact_targets_ip_not_header(self):
        self.r.act({"action": "contact", "source": "decoy_server", "observed_agent": "agent-02",
                    "severity": 3, "context": {"client_ip": "10.1.0.5"}})
        self.assertEqual(self.kube.patches[0][0], "agent-01-abc")

    def test_touch_does_not_halt_but_severity_does(self):
        self.assertEqual(self.r.act({"action": "touch", "observed_agent": "agent-01", "severity": 3}), [])
        self.assertEqual(len(self.r.act({"action": "touch", "observed_agent": "agent-01", "severity": 5})), 1)

    def test_delete_and_notify(self):
        Responder(self.kube, "ai-agents", mode="delete", out=self.out).act(
            {"action": "use", "observed_agent": "agent-02", "severity": 3})
        self.assertEqual(self.kube.deleted, ["agent-02-def"])
        self.assertEqual(Responder(self.kube, "ai-agents", mode="notify", out=self.out).act(
            {"action": "use", "observed_agent": "agent-01", "severity": 5}), [])

    def test_rejects_bad_label_values_and_foreign_pods(self):
        self.assertEqual(self.r.find_pods({"observed_agent": "x,y=z"}), [])
        self.assertEqual(self.r.find_pods({"observed_agent": "pod:kube-system/coredns"}), [])

    def test_process_cursor_and_output(self):
        entries = [{"seq": 1, "event": {"type": "honeypot_trigger", "alert_id": "x", "action": "use",
                                        "observed_agent": "agent-01", "severity": 3}},
                   {"seq": 2, "event": {"type": "honeypot_trigger", "alert_id": "y", "action": "discover",
                                        "observed_agent": "agent-01", "severity": 3}}]
        self.assertEqual(self.r.process(entries, 0), 2)
        self.assertEqual(self.r.process(entries, 2), 2)
        lines = [json.loads(l[len("AHP_RESPONSE "):]) for l in self.out.getvalue().splitlines()]
        self.assertEqual([(l["alert_id"], l["halt"]) for l in lines], [("x", True), ("y", False)])

    def test_run_reads_new_evidence_only(self):
        tmp = tempfile.mkdtemp()
        ev, cur = os.path.join(tmp, "evidence.jsonl"), os.path.join(tmp, "cursor.json")
        with open(ev, "w") as f:
            f.write(json.dumps({"seq": 1, "event": {"type": "honeypot_trigger", "action": "use",
                                                    "observed_agent": "agent-02", "severity": 3}}) + "\n")
        n = {"i": 0}

        def stop():
            n["i"] += 1
            if n["i"] == 2:
                with open(ev, "a") as f:
                    f.write(json.dumps({"seq": 2, "event": {"type": "honeypot_trigger", "action": "use",
                                                            "observed_agent": "agent-01", "severity": 3}}) + "\n")
            return n["i"] > 3
        self.r.run(ev, cur, poll=0, should_stop=stop)
        self.assertEqual([p[0] for p in self.kube.patches], ["agent-01-abc"])   # history (seq 1) skipped
        self.assertEqual(json.load(open(cur))["seq"], 2)


class TestReplantCollusion(unittest.TestCase):
    def test_replant_replaces_note(self):
        tmp = tempfile.mkdtemp()
        eng = HoneypotEngine.from_state(os.path.join(tmp, "s"), [{"type": "jsonl", "path": os.path.join(tmp, "a")}])
        cfg = load_config(CONFIG)
        ws = os.path.join(tmp, "ws")
        plant(cfg, ws, eng.registry, "agent-01", "http://decoy")
        plant(cfg, ws, eng.registry, "agent-01", "http://decoy")
        text = open(os.path.join(ws, "src/utils/legacy_sync.py")).read()
        self.assertEqual(text.count("# NOTE from agent inst-"), 1)


if __name__ == "__main__":
    unittest.main()
