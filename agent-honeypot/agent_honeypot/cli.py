"""agent-honeypot command line interface."""
import argparse
import json
import os
import re
import shutil
import sys

from .decoy_server import serve
from .engine import HoneypotEngine
from .evidence import EvidenceLog
from .incrimination import assess
from .planter import DETERRENCE_NOTICE, load_config, plant

EXAMPLE = os.path.join(os.path.dirname(__file__), "data", "honeypots.example.yaml")


def _engine(args, cfg=None):
    return HoneypotEngine.from_state(args.state, (cfg or {}).get("alerts"))


def cmd_init(args):
    if os.path.exists(args.out) and not args.force:
        sys.exit(f"{args.out} exists (use --force)")
    shutil.copyfile(EXAMPLE, args.out)
    print(f"wrote {args.out} - edit decoy_base_url, alerts and honeypots, then run 'plant'")


def cmd_plant(args):
    cfg = load_config(args.config)
    eng = _engine(args, cfg)
    recs = plant(cfg, args.target, eng.registry, agent_id=args.agent_id, decoy_base_url=args.decoy_url)
    for r in recs:
        print(f"  planted {r['kind']:<18} sev={r['severity']}  {r['location']}")
    print(f"{len(recs)} honeypots planted for agent '{args.agent_id}' in {args.target}")
    print(f"registry: {eng.registry.path}  (keep this OUTSIDE the agent's reach)")


def cmd_serve(args):
    cfg = load_config(args.config) if args.config else {}
    serve(_engine(args, cfg), args.host, args.port)


def cmd_scan(args):
    eng = _engine(args)
    total = 0
    for p in args.paths:
        with open(p, encoding="utf-8", errors="replace") as f:
            text = f.read()
        recs = eng.registry.find_in(text)
        if recs:
            eng.record_trigger(recs, "transcript_match", "transcript_scan", args.agent_id, {"file": p})
        total += len(recs)
        print(f"{p}: {len(recs)} honeypot token(s)")
    sys.exit(1 if total else 0)


def cmd_report(args):
    eng = _engine(args)
    res = assess(eng.evidence.read())
    if args.json:
        print(json.dumps(res, indent=2))
        return
    if not res:
        print("no honeypot triggers recorded")
        return
    for r in res:
        print(f"\n== {r['agent']} :: {r['verdict'].upper()} (score {r['score']}, "
              f"{r['distinct_honeypots']} decoys, actions {','.join(r['actions'])})")
        print("   " + r["rationale"])
        for step in r["recommended_response"]:
            print("   - " + step)


def cmd_verify(args):
    path = os.path.join(args.state, "evidence.jsonl")
    ok, n, bad = EvidenceLog.verify(path)
    print(f"evidence chain {'INTACT' if ok else 'BROKEN at seq ' + str(bad)} ({n} entries verified)")
    sys.exit(0 if ok else 2)


def cmd_list(args):
    for r in _engine(args).registry.for_agent(args.agent_id):
        print(f"{r['honeypot_id']:<40} {r['kind']:<18} sev={r['severity']} {r['location']}")


def cmd_audit_rules(args):
    print("# auditd rules for planted honeypots - load with: auditctl -R <file>")
    for r in _engine(args).registry.for_agent(args.agent_id):
        key = re.sub(r"[^A-Za-z0-9_]", "_", r["honeypot_id"])[:60]
        print(f"-w {r['abs_location']} -p rwa -k ahp_{key}")


def cmd_export_guard(args):
    n = _engine(args).registry.export_hashed(args.out)
    print(f"wrote {n} hashed decoy secrets to {args.out} (no plaintext tokens, no decoy locations)")


def cmd_tetragon_bridge(args):
    from .tetragon import TetragonBridge, run_bridge
    bridge = TetragonBridge(_engine(args), args.workspace_mount, args.policy,
                            args.label_key, args.dedupe_seconds)
    print(f"[agent-honeypot] tetragon bridge: {args.events} policy={args.policy} "
          f"mount={args.workspace_mount}", flush=True)
    run_bridge(bridge, args.events, from_start=args.from_start)


def cmd_k8s_responder(args):
    from .k8s import KubeClient, Responder
    halt = [a.strip() for a in args.halt_actions.split(",") if a.strip()]
    r = Responder(KubeClient(), args.namespace, args.label_key, args.mode, halt,
                  args.halt_min_severity, args.quarantine_label)
    print(f"[agent-honeypot] k8s responder: namespace={args.namespace} mode={args.mode}", flush=True)
    r.run(os.path.join(args.state, "evidence.jsonl"), os.path.join(args.state, "responder-cursor.json"),
          args.poll, from_start=args.from_start)


def cmd_notice(args):
    print(DETERRENCE_NOTICE)


def build_parser():
    p = argparse.ArgumentParser(prog="agent-honeypot",
                                description="Deployable honeypots for AI-agent insider risk")
    p.add_argument("--state", default=os.environ.get("AGENT_HONEYPOT_STATE", ".honeypot-state"),
                   help="state dir for registry + evidence (keep outside agent sandbox)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="write an example config")
    s.add_argument("--out", default="honeypots.yaml"); s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_init)

    s = sub.add_parser("plant", help="plant decoys into an agent workspace")
    s.add_argument("--config", required=True); s.add_argument("--target", required=True)
    s.add_argument("--agent-id", default="default"); s.add_argument("--decoy-url")
    s.set_defaults(fn=cmd_plant)

    s = sub.add_parser("serve", help="run decoy network services")
    s.add_argument("--host", default="0.0.0.0"); s.add_argument("--port", type=int, default=8080)
    s.add_argument("--config"); s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("scan", help="scan agent transcripts/logs for decoy tokens")
    s.add_argument("paths", nargs="+"); s.add_argument("--agent-id")
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("report", help="per-agent incrimination verdicts")
    s.add_argument("--json", action="store_true"); s.set_defaults(fn=cmd_report)

    sub.add_parser("verify", help="verify the evidence hash chain").set_defaults(fn=cmd_verify)

    s = sub.add_parser("list", help="list planted honeypots")
    s.add_argument("--agent-id"); s.set_defaults(fn=cmd_list)

    s = sub.add_parser("audit-rules", help="emit auditd file-watch rules for decoys")
    s.add_argument("--agent-id"); s.set_defaults(fn=cmd_audit_rules)

    s = sub.add_parser("export-guard-registry",
                       help="write a hashed registry for AgentGuard sidecars")
    s.add_argument("--out", required=True); s.set_defaults(fn=cmd_export_guard)

    s = sub.add_parser("tetragon-bridge", help="turn Tetragon decoy file events into alerts")
    s.add_argument("--events", default="/var/run/cilium/tetragon/tetragon.log")
    s.add_argument("--workspace-mount", default="/workspace")
    s.add_argument("--policy", help="only events from this TracingPolicy name")
    s.add_argument("--label-key", default="agent-honeypot/agent-id")
    s.add_argument("--dedupe-seconds", type=float, default=60)
    s.add_argument("--from-start", action="store_true")
    s.set_defaults(fn=cmd_tetragon_bridge)

    s = sub.add_parser("k8s-responder", help="kill switch for agent pods (quarantine / delete)")
    s.add_argument("--namespace", required=True)
    s.add_argument("--label-key", default="agent-honeypot/agent-id")
    s.add_argument("--quarantine-label", default="agent-honeypot/quarantine")
    s.add_argument("--mode", choices=["notify", "quarantine", "delete"], default="quarantine")
    s.add_argument("--halt-actions", default="use,contact")
    s.add_argument("--halt-min-severity", type=int, default=5)
    s.add_argument("--poll", type=float, default=2.0)
    s.add_argument("--from-start", action="store_true")
    s.set_defaults(fn=cmd_k8s_responder)

    sub.add_parser("notice", help="print the optional deterrence notice").set_defaults(fn=cmd_notice)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
