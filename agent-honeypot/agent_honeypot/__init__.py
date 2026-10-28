"""agent-honeypot: deployable deception controls for AI-agent insider risk.

Plant decoy opportunities (credentials, secrets, documents, model weights,
collusion invitations) into an agent's environment, detect any interaction
with them, attribute it to a specific agent instance, preserve tamper-evident
evidence, alert your SOC and halt the agent.
"""
from .engine import HoneypotEngine
from .guard import AgentGuard, HoneypotTriggered, AgentHalted
from .registry import HashedRegistry, Registry
from .planter import plant, load_config, DETERRENCE_NOTICE
from .incrimination import assess

__version__ = "0.1.0"
__all__ = ["HoneypotEngine", "AgentGuard", "HoneypotTriggered", "AgentHalted",
           "Registry", "HashedRegistry", "plant", "load_config", "assess", "DETERRENCE_NOTICE"]
