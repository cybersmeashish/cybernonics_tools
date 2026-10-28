"""CloudWatch Logs subscription -> WORM evidence (S3 Object Lock) + EventBridge.

Every container that runs agent-honeypot with the ``json_stdout`` alert sink
prints ``AHP_ALERT {json}``. This function decodes the subscription payload,
stores each alert as an immutable S3 object and forwards it to the
agent-honeypot event bus.
"""
import base64
import gzip
import hashlib
import json
import os
from datetime import datetime, timezone

PREFIX = "AHP_ALERT "
_clients = {}


def _client(name):
    if name not in _clients:
        import boto3
        _clients[name] = boto3.client(name)
    return _clients[name]


def decode(event):
    return json.loads(gzip.decompress(base64.b64decode(event["awslogs"]["data"])))


def extract_alerts(payload):
    alerts = []
    if payload.get("messageType") != "DATA_MESSAGE":
        return alerts
    for le in payload.get("logEvents", []):
        msg = le.get("message", "")
        i = msg.find(PREFIX)
        if i < 0:
            continue
        try:
            alert = json.loads(msg[i + len(PREFIX):].strip())
        except ValueError:
            continue
        if not isinstance(alert, dict) or alert.get("type") != "honeypot_trigger":
            continue
        alert["_log"] = {"group": payload.get("logGroup"), "stream": payload.get("logStream"),
                         "event_id": le.get("id")}
        alerts.append(alert)
    return alerts


def s3_key(alert):
    ts = alert.get("ts") or datetime.now(timezone.utc).isoformat()
    day = ts[:10].replace("-", "/")
    agent = str(alert.get("observed_agent", "unattributed")).replace("/", "_")
    return f"alerts/{day}/{agent}/{alert.get('alert_id', 'unknown')}.json"


def handler(event, context):
    alerts = extract_alerts(decode(event))
    if not alerts:
        return {"alerts": 0}
    s3, events = _client("s3"), _client("events")
    for a in alerts:
        body = json.dumps(a, sort_keys=True, default=str).encode("utf-8")
        s3.put_object(
            Bucket=os.environ["EVIDENCE_BUCKET"], Key=s3_key(a), Body=body,
            ContentType="application/json",
            ContentMD5=base64.b64encode(hashlib.md5(body).digest()).decode(),  # nosec - integrity header, not security
            ServerSideEncryption="aws:kms", SSEKMSKeyId=os.environ["KMS_KEY_ARN"])
    for i in range(0, len(alerts), 10):
        entries = [{"Source": "agent-honeypot", "DetailType": "Honeypot Trigger",
                    "Detail": json.dumps(a, default=str), "EventBusName": os.environ["EVENT_BUS_NAME"]}
                   for a in alerts[i:i + 10]]
        resp = events.put_events(Entries=entries)
        if resp.get("FailedEntryCount"):
            raise RuntimeError(f"EventBridge rejected {resp['FailedEntryCount']} entries")
    return {"alerts": len(alerts)}
