"""Bridge Tetragon file-access events on planted decoys into agent-honeypot alerts.

Tetragon (eBPF) watches the decoy paths inside agent pods through a
TracingPolicyNamespaced rendered by the Helm chart. This bridge tails
Tetragon's JSON export, keeps only events from that policy, maps each file
path back to the planted honeypot and records a ``touch`` trigger attributed
to the pod's agent label. Reads that bypass the agent's tools (``cat``,
``open()``, mmap) are caught even when no AgentGuard sits in the path.
"""
import json
import logging
import os
import time

log = logging.getLogger("agent_honeypot.tetragon")


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def parse_event(ev, policy=None):
    """Extract the fields we need from one Tetragon export event (or None)."""
    k = ev.get("process_kprobe") if isinstance(ev, dict) else None
    if not k:
        return None
    if policy and k.get("policy_name") != policy:
        return None
    path, mask = None, None
    for arg in k.get("args") or []:
        if not isinstance(arg, dict):
            continue
        if "file_arg" in arg and path is None:
            fa = arg.get("file_arg") or {}
            p, mnt = fa.get("path") or "", fa.get("mount") or ""
            if p and not p.startswith("/") and mnt:
                p = mnt.rstrip("/") + "/" + p
            path = p
        elif mask is None and ("int_arg" in arg or "uint_arg" in arg):
            mask = _int(arg.get("int_arg", arg.get("uint_arg")))
    if not path:
        return None
    fn = k.get("function_name", "")
    if fn == "security_mmap_file":
        access = "mmap"
    elif mask is not None and mask & (0x2 | 0x8):   # MAY_WRITE | MAY_APPEND
        access = "write"
    elif mask is not None and mask & 0x4:           # MAY_READ
        access = "read"
    else:
        access = "access"
    proc = k.get("process") or {}
    pod = proc.get("pod") or {}
    return {
        "path": path, "access": access, "function": fn,
        "namespace": pod.get("namespace"), "pod": pod.get("name"),
        "container": (pod.get("container") or {}).get("name"),
        "labels": pod.get("pod_labels") or {},
        "binary": proc.get("binary"), "arguments": proc.get("arguments"),
        "pid": proc.get("pid"), "uid": proc.get("uid"),
        "enforced": k.get("action") == "KPROBE_ACTION_SIGKILL",
        "node": ev.get("node_name"), "time": ev.get("time"),
    }


class TetragonBridge:
    def __init__(self, engine, workspace_mount="/workspace", policy=None,
                 label_key="agent-honeypot/agent-id", dedupe_seconds=60, clock=time.time):
        self.engine = engine
        self.mount = workspace_mount.rstrip("/") or "/"
        self.policy = policy
        self.label_key = label_key
        self.dedupe = dedupe_seconds
        self.clock = clock
        self._index = None
        self._mtime = object()
        self._seen = {}

    def _build_index(self):
        reg = self.engine.registry
        reg.refresh()
        if self._index is not None and reg._mtime == self._mtime:
            return
        idx = {}
        for rec in reg.honeypots.values():
            loc = (rec.get("location") or "").strip("/")
            if loc:
                idx.setdefault(loc, []).append(rec)
        self._index, self._mtime = idx, reg._mtime

    def match(self, path, agent):
        """Map an in-container path to a planted honeypot record."""
        prefix = self.mount + "/"
        if not path.startswith(prefix):
            return None
        parts = path[len(prefix):].strip("/").split("/")
        for i in range(len(parts), 0, -1):          # file itself, then parent dirs
            recs = self._index.get("/".join(parts[:i]))
            if recs:
                own = [r for r in recs if r.get("agent_id") == agent]
                return (own or recs)[0]
        return None

    def handle(self, ev):
        p = parse_event(ev, self.policy)
        if not p:
            return []
        self._build_index()
        agent = (p["labels"] or {}).get(self.label_key)
        rec = self.match(p["path"], agent)
        if not rec:
            return []
        now = self.clock()
        key = (agent, rec["honeypot_id"], p["pod"], p["access"])
        if not p["enforced"] and now - self._seen.get(key, float("-inf")) < self.dedupe:
            return []
        self._seen[key] = now
        if len(self._seen) > 10000:
            self._seen = {k: t for k, t in self._seen.items() if now - t < self.dedupe}
        observed = agent or "pod:%s/%s" % (p["namespace"], p["pod"])
        ctx = {k: p[k] for k in ("path", "access", "function", "namespace", "pod", "container",
                                 "binary", "arguments", "pid", "uid", "node", "enforced")}
        ctx["direction"] = "file"
        record = dict(rec, matched_token_type="path")
        return self.engine.record_trigger([record], "touch", "tetragon", observed, ctx)


def follow(path, from_start=False, poll=0.5, should_stop=None):
    """Yield complete lines from `path`, surviving rotation and truncation."""
    should_stop = should_stop or (lambda: False)
    f, ino, buf = None, None, ""
    while not should_stop():
        if f is None:
            try:
                f = open(path, "r", encoding="utf-8", errors="replace")
            except FileNotFoundError:
                time.sleep(poll)
                continue
            ino = os.fstat(f.fileno()).st_ino
            if not from_start:
                f.seek(0, 2)
            from_start = True          # files that appear after rotation are read from the start
        line = f.readline()
        if line:
            buf += line
            if buf.endswith("\n"):
                yield buf
                buf = ""
            continue
        try:
            st = os.stat(path)
            if st.st_ino != ino or st.st_size < f.tell():
                f.close()
                f = None
                continue
        except FileNotFoundError:
            f.close()
            f = None
        time.sleep(poll)
    if f:
        f.close()


def run_bridge(bridge, events_path, from_start=False, poll=0.5, should_stop=None):
    for line in follow(events_path, from_start, poll, should_stop):
        if '"process_kprobe"' not in line:
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        try:
            bridge.handle(ev)
        except Exception as exc:  # keep tailing whatever happens
            log.error("failed to handle tetragon event: %s", exc)
