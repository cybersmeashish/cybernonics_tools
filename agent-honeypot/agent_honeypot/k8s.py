"""Kubernetes responder: the kill switch for agent pods.

Tails the shared hash-chained evidence log and, for triggers that warrant a
halt, either quarantines or deletes the offending agent pod.

quarantine  strips every label except the agent id and adds
            ``<quarantine-label>=true``. The pod leaves its ReplicaSet,
            Services and label-selected NetworkPolicies, a deny-all
            NetworkPolicy (rendered by the chart) isolates it, and it keeps
            running so memory and processes stay available for forensics.
delete      deletes the pod (its controller may create a clean replacement).
notify      records the decision only.

Decoy-server triggers are targeted by the TCP client IP, never by the
self-reported X-Agent-Id header, so an agent cannot get a different agent
quarantined by spoofing that header.
"""
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
_LABEL_VALUE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,61}[A-Za-z0-9])?$")


class KubeClient:
    """Minimal in-cluster Kubernetes API client (stdlib only)."""

    def __init__(self, base_url=None, token_path=SA_DIR + "/token",
                 ca_path=SA_DIR + "/ca.crt", timeout=10):
        import ssl
        if base_url is None:
            host = os.environ["KUBERNETES_SERVICE_HOST"]
            port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
            if ":" in host:
                host = "[" + host + "]"
            base_url = "https://%s:%s" % (host, port)
        self.base = base_url.rstrip("/")
        self.token_path = token_path
        self.timeout = timeout
        self.ctx = ssl.create_default_context(cafile=ca_path if os.path.exists(ca_path) else None)

    def _req(self, method, path, body=None, content_type="application/json"):
        with open(self.token_path, encoding="utf-8") as f:
            token = f.read().strip()            # re-read: projected tokens rotate
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Authorization", "Bearer " + token)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", content_type)
        with urllib.request.urlopen(req, context=self.ctx, timeout=self.timeout) as r:
            raw = r.read()
        return json.loads(raw) if raw else {}

    def _pods(self, namespace):
        return "/api/v1/namespaces/%s/pods" % urllib.parse.quote(namespace, safe="")

    def list_pods(self, namespace, label_selector=None, field_selector=None):
        q = {}
        if label_selector:
            q["labelSelector"] = label_selector
        if field_selector:
            q["fieldSelector"] = field_selector
        path = self._pods(namespace) + ("?" + urllib.parse.urlencode(q) if q else "")
        return self._req("GET", path).get("items", [])

    def patch_pod_labels(self, namespace, name, labels):
        return self._req("PATCH", self._pods(namespace) + "/" + urllib.parse.quote(name, safe=""),
                         {"metadata": {"labels": labels}}, "application/merge-patch+json")

    def delete_pod(self, namespace, name):
        return self._req("DELETE", self._pods(namespace) + "/" + urllib.parse.quote(name, safe=""))


class Responder:
    def __init__(self, kube, namespace, label_key="agent-honeypot/agent-id", mode="quarantine",
                 halt_actions=("use", "contact"), halt_min_severity=5,
                 quarantine_label="agent-honeypot/quarantine", out=None):
        if mode not in ("notify", "quarantine", "delete"):
            raise ValueError("mode must be notify, quarantine or delete")
        self.kube = kube
        self.namespace = namespace
        self.label_key = label_key
        self.mode = mode
        self.halt_actions = set(halt_actions)
        self.min_sev = int(halt_min_severity)
        self.quarantine_label = quarantine_label
        self.out = out or sys.stdout

    def should_halt(self, a):
        return (a.get("action") in self.halt_actions or bool(a.get("cross_agent"))
                or int(a.get("severity", 0) or 0) >= self.min_sev)

    @staticmethod
    def target_of(a):
        ctx = a.get("context") or {}
        if a.get("source") == "decoy_server" and ctx.get("client_ip"):
            return "ip:" + str(ctx["client_ip"])
        return str(a.get("observed_agent") or "")

    def find_pods(self, a):
        t = self.target_of(a)
        if not t or t == "unattributed":
            return []
        if t.startswith("ip:"):
            pods = self.kube.list_pods(self.namespace, field_selector="status.podIP=" + t[3:])
        elif t.startswith("pod:"):
            ns, _, name = t[4:].partition("/")
            if ns != self.namespace or not name:
                return []
            pods = self.kube.list_pods(self.namespace, field_selector="metadata.name=" + name)
        else:
            if not _LABEL_VALUE.match(t):
                return []
            pods = self.kube.list_pods(self.namespace, label_selector="%s=%s" % (self.label_key, t))
        return [p for p in pods if (p.get("status") or {}).get("phase") in ("Running", "Pending")]

    def act(self, a):
        if self.mode == "notify" or not self.should_halt(a):
            return []
        actions = []
        for p in self.find_pods(a):
            md = p.get("metadata") or {}
            name = md.get("name")
            if self.mode == "delete":
                self.kube.delete_pod(self.namespace, name)
                actions.append({"deleted": name})
                continue
            labels = md.get("labels") or {}
            patch = {k: None for k in labels if k != self.label_key}
            patch[self.quarantine_label] = "true"
            aid = re.sub(r"[^A-Za-z0-9._-]", "", str(a.get("alert_id", "")))[:63].strip("._-")
            if aid:
                patch["agent-honeypot/alert-id"] = aid
            self.kube.patch_pod_labels(self.namespace, name, patch)
            actions.append({"quarantined": name,
                            "removed_labels": sorted(k for k in labels
                                                     if k not in (self.label_key, self.quarantine_label))})
        return actions

    def emit(self, record):
        self.out.write("AHP_RESPONSE " + json.dumps(record, default=str, separators=(",", ":")) + "\n")
        self.out.flush()

    def process(self, entries, cursor):
        for e in entries:
            seq = int(e.get("seq", 0) or 0)
            if seq <= cursor:
                continue
            ev = e.get("event") or {}
            if ev.get("type") == "honeypot_trigger":
                err = None
                try:
                    actions = self.act(ev)
                except Exception as exc:  # report, never crash the loop
                    actions, err = [], str(exc)
                self.emit({"type": "honeypot_response", "evidence_seq": seq,
                           "alert_id": ev.get("alert_id"), "action": ev.get("action"),
                           "target": self.target_of(ev), "mode": self.mode,
                           "halt": self.should_halt(ev), "actions": actions, "error": err})
            cursor = seq
        return cursor

    def run(self, evidence_path, cursor_path, poll=2.0, from_start=False, should_stop=None):
        should_stop = should_stop or (lambda: False)
        cursor = _load_cursor(cursor_path)
        if cursor is None:
            cursor = 0 if from_start else _last_seq(evidence_path)
            _save_cursor(cursor_path, cursor)
        pos, pending = 0, b""
        while not should_stop():
            try:
                size = os.path.getsize(evidence_path)
            except OSError:
                size = None
            if size is not None:
                if size < pos:
                    pos, pending = 0, b""
                if size > pos:
                    with open(evidence_path, "rb") as f:
                        f.seek(pos)
                        chunk = f.read(size - pos)
                    pos += len(chunk)
                    data = pending + chunk
                    cut = data.rfind(b"\n") + 1
                    pending = data[cut:]
                    entries = []
                    for line in data[:cut].decode("utf-8", "replace").splitlines():
                        if line.strip():
                            try:
                                entries.append(json.loads(line))
                            except ValueError:
                                pass
                    new = self.process(entries, cursor)
                    if new != cursor:
                        cursor = new
                        _save_cursor(cursor_path, cursor)
            time.sleep(poll)


def _load_cursor(path):
    try:
        with open(path, encoding="utf-8") as f:
            return int(json.load(f)["seq"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _save_cursor(path, seq):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"seq": seq}, f)
    os.replace(tmp, path)


def _last_seq(path):
    last = 0
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        last = int(json.loads(line).get("seq", last))
                    except ValueError:
                        pass
    except OSError:
        pass
    return last
