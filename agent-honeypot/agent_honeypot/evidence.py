"""Append-only, hash-chained evidence log (tamper-evident).

Each entry stores the SHA-256 of the previous entry. Editing or deleting any
line breaks the chain, which `EvidenceLog.verify` detects. For production,
ship the log to WORM storage (e.g. S3 Object Lock) as well.
"""
import hashlib
import json
import os
import threading
from datetime import datetime, timezone

GENESIS = "0" * 64

try:  # POSIX advisory lock so multiple processes can share one log
    import fcntl

    def _lock(f):
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)

    def _unlock(f):
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
except ImportError:  # pragma: no cover - Windows
    def _lock(f):
        pass

    def _unlock(f):
        pass


def _now():
    return datetime.now(timezone.utc).isoformat()


def _digest(entry):
    body = {k: v for k, v in entry.items() if k != "hash"}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class EvidenceLog:
    def __init__(self, path):
        self.path = path
        self._tlock = threading.Lock()

    def append(self, event):
        with self._tlock:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            with open(self.path, "a+", encoding="utf-8") as f:
                _lock(f)
                try:
                    f.seek(0)
                    last = None
                    for line in f:
                        if line.strip():
                            last = line
                    prev = json.loads(last) if last else None
                    entry = {
                        "seq": (prev["seq"] + 1) if prev else 1,
                        "ts": _now(),
                        "event": event,
                        "prev_hash": prev["hash"] if prev else GENESIS,
                    }
                    entry["hash"] = _digest(entry)
                    f.seek(0, 2)
                    f.write(json.dumps(entry, sort_keys=True, default=str) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
                finally:
                    _unlock(f)
            return entry

    def read(self):
        if not os.path.exists(self.path):
            return []
        out = []
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    out.append(json.loads(line))
        return out

    @staticmethod
    def verify(path):
        """Return (ok, entries_checked, first_bad_seq)."""
        prev = GENESIS
        n = 0
        if not os.path.exists(path):
            return True, 0, None
        with open(path, encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    return False, n, n + 1
                if e.get("prev_hash") != prev or _digest(e) != e.get("hash"):
                    return False, n, e.get("seq", n + 1)
                prev = e["hash"]
                n += 1
        return True, n, None
