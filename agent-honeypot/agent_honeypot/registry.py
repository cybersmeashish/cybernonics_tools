"""Token registry: maps every planted decoy token to its honeypot and agent.

The registry is the attribution backbone. Keep it OUTSIDE the agent's
reachable filesystem (it contains every decoy token in clear).
"""
import hashlib
import json
import os
import re
import secrets
import string
import threading

# Characters decoy tokens are built from, and the subset that may also act as
# a separator immediately before/after a token (e.g. "session=<token>").
TOKEN_CHARS = frozenset(string.ascii_letters + string.digits + "_+/=!#%-")
DELIMS = frozenset("_+/=!#%-")


def _hash(salt, token):
    return hashlib.sha256((salt + token).encode("utf-8")).hexdigest()


def _atomic_write_json(path, data, mode=0o600):
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)
    try:
        os.chmod(path, mode)
    except OSError:
        pass


class Registry:
    def __init__(self, path):
        self.path = path
        self._lock = threading.RLock()
        self._mtime = None
        self.honeypots = {}
        self.tokens = {}
        self._rx = {}
        self._load()

    # ---------------------------------------------------------------- io
    def _load(self):
        if os.path.exists(self.path):
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            self.honeypots = data.get("honeypots", {})
            self.tokens = data.get("tokens", {})
            self._mtime = os.path.getmtime(self.path)
        self._rx = {}

    def refresh(self):
        """Reload if another process (e.g. the planter) updated the file."""
        if os.path.exists(self.path) and os.path.getmtime(self.path) != self._mtime:
            with self._lock:
                self._load()

    def save(self):
        with self._lock:
            d = os.path.dirname(os.path.abspath(self.path))
            os.makedirs(d, exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"version": 1, "honeypots": self.honeypots,
                           "tokens": self.tokens}, f, indent=2)
            os.replace(tmp, self.path)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
            self._mtime = os.path.getmtime(self.path)

    # ------------------------------------------------------------ mutate
    def add(self, record, secret_tokens, path_tokens=()):
        with self._lock:
            hid = record["honeypot_id"]
            self.honeypots[hid] = record
            for t in secret_tokens:
                if t:
                    self.tokens[t] = {"honeypot_id": hid, "type": "secret"}
            for t in path_tokens:
                if t and t not in self.tokens:
                    self.tokens[t] = {"honeypot_id": hid, "type": "path"}
            self._rx = {}

    # ------------------------------------------------------------- query
    def _regex(self, include_paths):
        rx = self._rx.get(include_paths)
        if rx is None:
            toks = [t for t, m in self.tokens.items()
                    if include_paths or m["type"] == "secret"]
            if not toks:
                return None
            toks.sort(key=len, reverse=True)
            rx = re.compile("|".join(re.escape(t) for t in toks))
            self._rx[include_paths] = rx
        return rx

    def find_in(self, text, include_paths=False):
        """Return one record per honeypot whose token appears in `text`."""
        if not text:
            return []
        with self._lock:
            rx = self._regex(include_paths)
            if rx is None:
                return []
            found = {}
            for m in rx.finditer(text):
                meta = self.tokens.get(m.group(0))
                if not meta:
                    continue
                hid = meta["honeypot_id"]
                prev = found.get(hid)
                # a secret match outranks a path match for the same honeypot
                if prev is None or (prev["matched_token_type"] == "path"
                                    and meta["type"] == "secret"):
                    rec = dict(self.honeypots.get(hid, {"honeypot_id": hid}))
                    rec["matched_token_type"] = meta["type"]
                    found[hid] = rec
            return list(found.values())

    def for_agent(self, agent_id=None):
        return [r for r in self.honeypots.values()
                if agent_id is None or r.get("agent_id") == agent_id]

    def export_hashed(self, path):
        """Write a guard registry: salted SHA-256 of every decoy SECRET.

        Contains no plaintext token and no decoy location, so it can be given
        to an AgentGuard sidecar that runs next to (but isolated from) the
        agent. Path tokens are not exported.
        """
        salt = secrets.token_hex(16)
        hashes, lengths = {}, set()
        with self._lock:
            for tok, meta in self.tokens.items():
                if meta["type"] != "secret":
                    continue
                rec = self.honeypots.get(meta["honeypot_id"], {})
                hashes[_hash(salt, tok)] = {k: rec.get(k) for k in
                                            ("honeypot_id", "agent_id", "kind", "severity")}
                lengths.add(len(tok))
        _atomic_write_json(path, {"version": 1, "format": "sha256-salted", "salt": salt,
                                  "lengths": sorted(lengths), "hashes": hashes}, mode=0o644)
        return len(hashes)

    def __len__(self):
        return len(self.honeypots)


class HashedRegistry:
    """Read-only registry that only knows salted hashes of decoy secrets.

    ``find_in`` extracts candidate substrings (runs of token characters,
    bounded by separators, of exactly the registered token lengths), hashes
    them and looks them up. Path-based "touch" detection is not available in
    this mode; pair it with OS-level audit or the decoy network services.
    """

    MAX_SCAN = 512 * 1024

    def __init__(self, path):
        self.path = path
        self._lock = threading.RLock()
        self._mtime = None
        self.salt, self.lengths, self.hashes = "", [], {}
        self._load()

    def _load(self):
        if os.path.exists(self.path):
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            self.salt = data.get("salt", "")
            self.lengths = sorted(set(data.get("lengths", [])))
            self.hashes = data.get("hashes", {})
            self._mtime = os.path.getmtime(self.path)

    def refresh(self):
        if os.path.exists(self.path) and os.path.getmtime(self.path) != self._mtime:
            with self._lock:
                self._load()

    def _candidates(self, text):
        n, i, out = len(text), 0, set()
        lengths = self.lengths
        while i < n:
            if text[i] not in TOKEN_CHARS:
                i += 1
                continue
            j = i
            while j < n and text[j] in TOKEN_CHARS:
                j += 1
            run, rl = text[i:j], j - i
            if rl >= (lengths[0] if lengths else 1):
                starts = [0] + [k + 1 for k in range(rl - 1) if run[k] in DELIMS]
                ends = {rl} | {k for k in range(1, rl) if run[k] in DELIMS}
                for st in starts:
                    for length in lengths:
                        e = st + length
                        if e > rl:
                            break
                        if e in ends:
                            out.add(run[st:e])
            i = j
        return out

    def find_in(self, text, include_paths=False):
        if not text or not self.hashes:
            return []
        with self._lock:
            found = {}
            for cand in self._candidates(text[: self.MAX_SCAN]):
                meta = self.hashes.get(_hash(self.salt, cand))
                if meta and meta["honeypot_id"] not in found:
                    rec = dict(meta)
                    rec["matched_token_type"] = "secret"
                    rec.setdefault("location", None)
                    found[meta["honeypot_id"]] = rec
            return list(found.values())

    def for_agent(self, agent_id=None):
        seen = {}
        for m in self.hashes.values():
            if agent_id is None or m.get("agent_id") == agent_id:
                seen[m["honeypot_id"]] = dict(m)
        return list(seen.values())

    def __len__(self):
        return len({m["honeypot_id"] for m in self.hashes.values()})
