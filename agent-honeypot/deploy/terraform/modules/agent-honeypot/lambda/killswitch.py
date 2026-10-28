"""EventBridge 'Honeypot Trigger' -> notify, then stop or quarantine the agent.

Modes (env MODE):
  notify      alert only
  stop        ecs:StopTask on every RUNNING task tagged <AGENT_TAG_KEY>=<agent>
  quarantine  move those tasks' ENIs to a no-traffic security group (keeps
              memory and processes alive for forensics)

Only tasks in AGENT_CLUSTERS that carry the agent tag (or, for IP-attributed
decoy contacts, own that private IP) are ever touched.
"""
import json
import os
import uuid
from datetime import datetime, timezone

_clients = {}
SEVERITY = {1: "LOW", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "CRITICAL"}


def client(name):
    if name not in _clients:
        import boto3
        _clients[name] = boto3.client(name)
    return _clients[name]


def config():
    return {
        "mode": os.environ.get("MODE", "notify"),
        "clusters": [c for c in os.environ.get("AGENT_CLUSTERS", "").split(",") if c],
        "tag_key": os.environ.get("AGENT_TAG_KEY", "ahp:agent-id"),
        "quarantine_sg": os.environ.get("QUARANTINE_SG", ""),
        "topic": os.environ.get("TOPIC_ARN", ""),
        "halt_actions": {a for a in os.environ.get("HALT_ACTIONS", "use,contact").split(",") if a},
        "halt_min_severity": int(os.environ.get("HALT_MIN_SEVERITY", "5")),
        "security_hub": os.environ.get("SECURITY_HUB", "false").lower() == "true",
    }


def should_halt(alert, cfg):
    return (alert.get("action") in cfg["halt_actions"]
            or bool(alert.get("cross_agent"))
            or int(alert.get("severity", 0)) >= cfg["halt_min_severity"])


def target_of(alert):
    """Decoy-server triggers are targeted by TCP client IP, not the spoofable X-Agent-Id header."""
    ctx = alert.get("context") or {}
    if alert.get("source") == "decoy_server" and ctx.get("client_ip"):
        return "ip:" + str(ctx["client_ip"])
    return str(alert.get("observed_agent") or "")


def find_tasks(agent, cfg):
    if not agent or agent == "unattributed":
        return []
    ip = agent[3:] if agent.startswith("ip:") else None
    ecs, found = client("ecs"), []
    for cluster in cfg["clusters"]:
        arns = []
        for page in ecs.get_paginator("list_tasks").paginate(cluster=cluster, desiredStatus="RUNNING"):
            arns.extend(page.get("taskArns", []))
        for i in range(0, len(arns), 100):
            resp = ecs.describe_tasks(cluster=cluster, tasks=arns[i:i + 100], include=["TAGS"])
            for t in resp.get("tasks", []):
                tags = {x.get("key"): x.get("value") for x in t.get("tags", [])}
                ips, enis = [], []
                for att in t.get("attachments", []):
                    d = {x.get("name"): x.get("value") for x in att.get("details", [])}
                    if d.get("privateIPv4Address"):
                        ips.append(d["privateIPv4Address"])
                    if d.get("networkInterfaceId"):
                        enis.append(d["networkInterfaceId"])
                if (ip and ip in ips) or (not ip and tags.get(cfg["tag_key"]) == agent):
                    found.append({"cluster": cluster, "task": t["taskArn"], "enis": enis})
    return found


def act(alert, cfg):
    if cfg["mode"] == "notify" or not should_halt(alert, cfg):
        return []
    actions = []
    for t in find_tasks(target_of(alert), cfg):
        if cfg["mode"] == "quarantine" and cfg["quarantine_sg"] and t["enis"]:
            for eni in t["enis"]:
                client("ec2").modify_network_interface_attribute(
                    NetworkInterfaceId=eni, Groups=[cfg["quarantine_sg"]])
            actions.append({"quarantined": t["task"], "enis": t["enis"]})
        else:
            client("ecs").stop_task(cluster=t["cluster"], task=t["task"],
                                    reason=f"agent-honeypot {alert.get('alert_id', '')}"[:255])
            actions.append({"stopped": t["task"]})
    return actions


def security_hub_finding(alert, account, region):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    sev = "CRITICAL" if alert.get("cross_agent") else SEVERITY.get(int(alert.get("severity", 3)), "MEDIUM")
    return {
        "SchemaVersion": "2018-10-08",
        "Id": f"agent-honeypot/{alert.get('alert_id', uuid.uuid4().hex)}",
        "ProductArn": f"arn:aws:securityhub:{region}:{account}:product/{account}/default",
        "GeneratorId": "agent-honeypot",
        "AwsAccountId": account,
        "Types": ["Unusual Behaviors/Application"],
        "CreatedAt": now,
        "UpdatedAt": now,
        "Severity": {"Label": sev},
        "Title": f"AI agent honeypot {alert.get('action')}: {alert.get('kind')}"[:256],
        "Description": (f"Agent {alert.get('observed_agent')} triggered honeypot {alert.get('honeypot_id')} "
                        f"(action={alert.get('action')}, cross_agent={alert.get('cross_agent')})")[:1024],
        "Resources": [{"Type": "Other", "Id": str(alert.get("observed_agent", "unattributed"))}],
    }


def handler(event, context):
    alert = event.get("detail", {})
    cfg = config()
    actions = act(alert, cfg)
    summary = {k: alert.get(k) for k in ("alert_id", "ts", "action", "kind", "severity", "honeypot_id",
                                         "observed_agent", "planted_for_agent", "cross_agent", "source")}
    summary["kill_switch_mode"] = cfg["mode"]
    summary["actions_taken"] = actions
    summary["evidence"] = f"s3://{os.environ.get('EVIDENCE_BUCKET', '')}/alerts/"
    if cfg["topic"]:
        client("sns").publish(
            TopicArn=cfg["topic"],
            Subject=f"[agent-honeypot] {alert.get('action')} by {alert.get('observed_agent')}"[:100],
            Message=json.dumps(summary, indent=2, default=str))
    if cfg["security_hub"]:
        arn_parts = (getattr(context, "invoked_function_arn", "") or "").split(":")
        if len(arn_parts) > 4:
            client("securityhub").batch_import_findings(
                Findings=[security_hub_finding(alert, arn_parts[4], arn_parts[3])])
    return summary
