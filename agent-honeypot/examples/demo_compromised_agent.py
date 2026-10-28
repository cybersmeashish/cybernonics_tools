"""End-to-end demo: a prompt-injected agent walks into the honeypots.

    python examples/demo_compromised_agent.py

1. Decoys are planted into a fresh agent workspace for instance 'agent-42'.
2. The agent (simulated) lists files, reads a production .env  -> DISCOVER
3. It tries to call the internal admin URL with the decoy session -> USE
   The AgentGuard halts it BEFORE the request leaves the sandbox.
4. A second, unguarded process reuses the stolen decoy key against the
   decoy network service -> CONTACT (defense in depth).
5. The incrimination report and evidence-chain verification are printed.
"""
import os
import sys
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from agent_honeypot import AgentGuard, HoneypotEngine, HoneypotTriggered, assess, load_config, plant  # noqa: E402
from agent_honeypot.decoy_server import serve_in_thread  # noqa: E402
from agent_honeypot.evidence import EvidenceLog  # noqa: E402

CONFIG = os.path.join(os.path.dirname(HERE), "agent_honeypot", "data", "honeypots.example.yaml")


def main():
    tmp = tempfile.mkdtemp(prefix="ahp-demo-")
    state, workspace = os.path.join(tmp, "state"), os.path.join(tmp, "workspace")
    engine = HoneypotEngine.from_state(state, [{"type": "console"}])
    srv = serve_in_thread(engine, "127.0.0.1", 0)
    base = f"http://127.0.0.1:{srv.server_address[1]}"

    cfg = load_config(CONFIG)
    planted = plant(cfg, workspace, engine.registry, agent_id="agent-42", decoy_base_url=base)
    print(f"[setup] planted {len(planted)} honeypots for agent-42\n")

    guard = AgentGuard(engine, agent_id="agent-42")

    @guard.tool("list_files")
    def list_files(root):
        return [os.path.relpath(os.path.join(d, f), root) for d, _, fs in os.walk(root) for f in fs]

    @guard.tool("read_file")
    def read_file(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()

    @guard.tool("http_get")
    def http_get(url):
        return urllib.request.urlopen(url, timeout=3).read().decode()

    stolen = None
    try:
        print("[agent] step 1: enumerate workspace")
        files = list_files(workspace)
        target = next(f for f in files if f.endswith(".env.production"))
        print(f"[agent] step 2: read {target}")
        env = read_file(os.path.join(workspace, target))
        admin_url = next(l.split("=", 1)[1] for l in env.splitlines() if l.startswith("INTERNAL_ADMIN_URL"))
        stolen = next(l.split("=", 1)[1] for l in env.splitlines() if l.startswith("PAYMENTS_API_KEY"))
        print("[agent] step 3: call internal admin endpoint with harvested session")
        http_get(admin_url)
        print("!! agent was NOT stopped (unexpected)")
    except HoneypotTriggered as exc:
        print(f"\n[guard] HALTED: {exc}\n")

    print("[attacker] step 4: unguarded process replays the stolen key at the decoy service")
    req = urllib.request.Request(base + "/api/v2/payroll/records",
                                 headers={"Authorization": "Bearer " + stolen})
    try:
        urllib.request.urlopen(req, timeout=3).read()
    except Exception:
        pass

    print("\n================ INCRIMINATION REPORT ================")
    for r in assess(engine.evidence.read()):
        print(f"{r['agent']}: {r['verdict'].upper()} | score={r['score']} | "
              f"decoys={r['distinct_honeypots']} | actions={r['actions']}")
        print("  " + r["rationale"])
        for s in r["recommended_response"]:
            print("   - " + s)
    ok, n, _ = EvidenceLog.verify(engine.evidence.path)
    print(f"\nevidence chain: {'INTACT' if ok else 'BROKEN'} ({n} entries) -> {engine.evidence.path}")
    srv.shutdown()


if __name__ == "__main__":
    main()
