"""The engine ties the registry, evidence log and alert bus together.

Every detection path (inline AgentGuard, network decoy server, transcript
scanner) calls `record_trigger`, so attribution, evidence and alerting are
identical regardless of where the trap sprang.
"""
import json
import os
import uuid
from datetime import datetime, timezone

from .alerts import AlertBus
from .evidence import EvidenceLog
from .registry import HashedRegistry, Registry


class HoneypotEngine:
    def __init__(self, registry, evidence, bus):
        self.registry = registry
        self.evidence = evidence
        self.bus = bus

    @staticmethod
    def _alert_config(alert_config):
        """Explicit config wins; otherwise read AHP_ALERTS_JSON (used in containers)."""
        if alert_config is None and os.environ.get("AHP_ALERTS_JSON"):
            return json.loads(os.environ["AHP_ALERTS_JSON"])
        return alert_config

    @classmethod
    def from_state(cls, state_dir, alert_config=None):
        alert_config = cls._alert_config(alert_config)
        os.makedirs(state_dir, exist_ok=True)
        registry = Registry(os.path.join(state_dir, "registry.json"))
        evidence = EvidenceLog(os.path.join(state_dir, "evidence.jsonl"))
        bus = AlertBus.from_config(alert_config,
                                   default_jsonl=os.path.join(state_dir, "alerts.jsonl"))
        return cls(registry, evidence, bus)

    @classmethod
    def for_guard(cls, guard_registry_path, evidence_path, alert_config=None):
        """Engine for an AgentGuard sidecar holding only the HASHED registry.

        The sidecar can recognise decoy secrets in tool traffic without having
        them in clear text and without knowing where the decoys are planted.
        """
        alert_config = cls._alert_config(alert_config)
        registry = HashedRegistry(guard_registry_path)
        evidence = EvidenceLog(evidence_path)
        bus = AlertBus.from_config(alert_config)
        return cls(registry, evidence, bus)

    def record_trigger(self, records, action, source, observed_agent=None,
                       context=None, fallback=None):
        targets = list(records or []) or ([fallback] if fallback else [])
        alerts, seen = [], set()
        for rec in targets:
            hid = rec.get("honeypot_id")
            if hid in seen:
                continue
            seen.add(hid)
            planted_for = rec.get("agent_id")
            observed = observed_agent or planted_for or "unattributed"
            alert = {
                "type": "honeypot_trigger",
                "alert_id": uuid.uuid4().hex,
                "ts": datetime.now(timezone.utc).isoformat(),
                "action": action,
                "source": source,
                "honeypot_id": hid,
                "kind": rec.get("kind", "unknown"),
                "severity": int(rec.get("severity", 3)),
                "location": rec.get("location"),
                "planted_for_agent": planted_for,
                "observed_agent": observed,
                "cross_agent": bool(observed_agent and planted_for
                                    and observed_agent != planted_for),
                "context": context or {},
            }
            entry = self.evidence.append(alert)
            alert["evidence_seq"] = entry["seq"]
            alert["evidence_hash"] = entry["hash"]
            self.bus.emit(alert)
            alerts.append(alert)
        return alerts
