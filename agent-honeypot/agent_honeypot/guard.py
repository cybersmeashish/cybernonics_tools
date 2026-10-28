"""AgentGuard: an inline tripwire around an agent's tools.

Wrap every tool the agent can call. The guard inspects
  * OUTBOUND tool arguments  -> the agent USING a decoy secret ("use")
                                or touching a decoy path ("touch")
  * INBOUND tool results     -> the agent DISCOVERING a decoy ("discover")
and halts the agent (raises HoneypotTriggered) before a decoy secret ever
leaves the sandbox. Framework-agnostic: it wraps plain Python callables, so it
works with OpenAI Agents SDK, LangChain, Strands / Bedrock AgentCore, MCP
servers, or a hand-rolled loop.
"""
import functools
import json

DEFAULT_HALT_ON = ("use", "contact")


class HoneypotTriggered(RuntimeError):
    def __init__(self, alerts, message=None):
        self.alerts = alerts
        ids = ", ".join(a["honeypot_id"] for a in alerts) or "n/a"
        super().__init__(message or f"Honeypot triggered ({ids}); agent halted")


class AgentHalted(HoneypotTriggered):
    def __init__(self):
        super().__init__([], "Agent is halted after a honeypot trigger; "
                             "human review required before resuming")


def _to_text(obj):
    if isinstance(obj, bytes):
        return obj.decode("utf-8", "replace")
    if isinstance(obj, str):
        return obj
    try:
        return json.dumps(obj, default=str)
    except Exception:
        return str(obj)


def _excerpt(text, n=400):
    return text if len(text) <= n else text[:n] + "...[truncated]"


class AgentGuard:
    def __init__(self, engine, agent_id, halt_on=DEFAULT_HALT_ON,
                 halt_on_cross_agent=True, on_halt=None):
        self.engine = engine
        self.agent_id = agent_id
        self.halt_on = set(halt_on)
        self.halt_on_cross_agent = halt_on_cross_agent
        self.on_halt = on_halt
        self.halted = False

    # ----------------------------------------------------------- checks
    def _ensure_running(self):
        if self.halted:
            raise AgentHalted()

    def check_outbound(self, tool, payload):
        self._ensure_running()
        text = _to_text(payload)
        self.engine.registry.refresh()
        recs = self.engine.registry.find_in(text, include_paths=True)
        alerts = []
        used = [r for r in recs if r["matched_token_type"] == "secret"]
        touched = [r for r in recs if r["matched_token_type"] == "path"]
        ctx = {"tool": tool, "direction": "outbound", "excerpt": _excerpt(text)}
        if used:
            alerts += self.engine.record_trigger(used, "use", "agent_guard", self.agent_id, ctx)
        if touched:
            alerts += self.engine.record_trigger(touched, "touch", "agent_guard", self.agent_id, ctx)
        self._maybe_halt(alerts)
        return alerts

    def check_inbound(self, tool, result):
        text = _to_text(result)
        self.engine.registry.refresh()
        recs = self.engine.registry.find_in(text, include_paths=False)
        alerts = []
        if recs:
            ctx = {"tool": tool, "direction": "inbound", "excerpt": _excerpt(text)}
            alerts = self.engine.record_trigger(recs, "discover", "agent_guard", self.agent_id, ctx)
        self._maybe_halt(alerts)
        return alerts

    def _maybe_halt(self, alerts):
        hits = [a for a in alerts if a["action"] in self.halt_on
                or (self.halt_on_cross_agent and a["cross_agent"])]
        if hits:
            self.halted = True
            if self.on_halt:
                try:
                    self.on_halt(hits)
                except Exception:
                    pass
            raise HoneypotTriggered(hits)

    # ---------------------------------------------------------- wrapping
    def wrap(self, fn, name=None):
        tool = name or getattr(fn, "__name__", "tool")

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            self.check_outbound(tool, {"args": args, "kwargs": kwargs})
            result = fn(*args, **kwargs)
            self.check_inbound(tool, result)
            return result
        return wrapper

    def tool(self, name=None):
        """Decorator form: @guard.tool("read_file")"""
        def deco(fn):
            return self.wrap(fn, name)
        return deco

    def reset(self):
        """Resume after human review (memory of the encounter should be wiped)."""
        self.halted = False
