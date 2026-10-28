"""Alert sinks: console, JSONL (for SIEM shipping), generic webhook, Slack."""
import json
import logging
import os
import sys
import urllib.request

log = logging.getLogger("agent_honeypot")


def _summary(a):
    return ("HONEYPOT TRIGGERED | sev={severity} action={action} agent={observed_agent} "
            "honeypot={honeypot_id} kind={kind} cross_agent={cross_agent}").format(**a)


class ConsoleSink:
    def send(self, alert):
        sys.stderr.write("[agent-honeypot] " + _summary(alert) + "\n")


class JsonlSink:
    def __init__(self, path):
        self.path = path

    def send(self, alert):
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert, default=str) + "\n")


class JsonStdoutSink:
    """One JSON line per alert on stdout, prefixed ``AHP_ALERT``.

    Designed for log shippers: CloudWatch Logs subscription filters, Fluent Bit,
    Vector, etc. The AWS Terraform deployment relies on this sink.
    """
    PREFIX = "AHP_ALERT "

    def send(self, alert):
        sys.stdout.write(self.PREFIX + json.dumps(alert, default=str, separators=(",", ":")) + "\n")
        sys.stdout.flush()


class WebhookSink:
    """POST alerts to a webhook. style='slack' sends a Slack-compatible body."""

    def __init__(self, url, style="json", headers=None, timeout=3):
        self.url = os.path.expandvars(url)
        self.style = style
        self.headers = headers or {}
        self.timeout = timeout

    def send(self, alert):
        if self.style == "slack":
            body = {"text": ":rotating_light: " + _summary(alert)
                    + "\nlocation: " + str(alert.get("location"))}
        else:
            body = alert
        data = json.dumps(body, default=str).encode("utf-8")
        req = urllib.request.Request(self.url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        for k, v in self.headers.items():
            req.add_header(k, os.path.expandvars(str(v)))
        urllib.request.urlopen(req, timeout=self.timeout).read()


class AlertBus:
    def __init__(self, sinks):
        self.sinks = list(sinks)

    def emit(self, alert):
        for s in self.sinks:
            try:
                s.send(alert)
            except Exception as exc:  # never let a sink failure hide an alert
                log.error("alert sink %s failed: %s", type(s).__name__, exc)

    @classmethod
    def from_config(cls, items, default_jsonl=None):
        sinks = []
        for it in items or []:
            t = it.get("type")
            if t == "console":
                sinks.append(ConsoleSink())
            elif t == "json_stdout":
                sinks.append(JsonStdoutSink())
            elif t == "jsonl":
                sinks.append(JsonlSink(it.get("path") or default_jsonl))
            elif t in ("webhook", "slack"):
                sinks.append(WebhookSink(it["url"], style=it.get("style", "slack" if t == "slack" else "json"),
                                         headers=it.get("headers")))
            else:
                log.warning("unknown alert sink type: %s", t)
        if not sinks:
            sinks = [ConsoleSink()] + ([JsonlSink(default_jsonl)] if default_jsonl else [])
        return cls(sinks)
