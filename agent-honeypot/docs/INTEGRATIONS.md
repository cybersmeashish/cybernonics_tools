# Integrating AgentGuard with agent frameworks

The rule is simple: **wrap the underlying Python function with `guard.wrap(...)` before you register it as a tool.** `functools.wraps` preserves the name, docstring and signature that frameworks use to build tool schemas.

```python
from agent_honeypot import HoneypotEngine, AgentGuard
engine = HoneypotEngine.from_state("/secure/ahp-state", alert_config=[
    {"type": "console"},
    {"type": "webhook", "url": "https://soc.example.com/hooks/ahp"},
])
guard = AgentGuard(engine, agent_id="agent-01", on_halt=lambda alerts: kill_switch(alerts))
```

## Generic / custom agent loop
```python
TOOLS = {name: guard.wrap(fn, name) for name, fn in RAW_TOOLS.items()}
try:
    result = TOOLS[call.name](**call.arguments)
except HoneypotTriggered as e:
    # stop the loop; do NOT return the error text to the model
    quarantine(agent_id, e.alerts)
```

## OpenAI Agents SDK
```python
from agents import function_tool
read_file_tool = function_tool(guard.wrap(read_file, "read_file"))
```

## LangChain
```python
from langchain_core.tools import StructuredTool
tool = StructuredTool.from_function(guard.wrap(read_file, "read_file"))
```

## Strands Agents / Amazon Bedrock AgentCore
```python
from strands import tool
read_file_tool = tool(guard.wrap(read_file, "read_file"))
```

## MCP servers
Wrap each handler inside your MCP server, or run a thin MCP proxy in front of third-party servers that calls `guard.check_outbound(tool, args)` before forwarding and `guard.check_inbound(tool, result)` on the response.

## Decoy-server attribution header
If your scaffold controls outbound HTTP, inject `X-Agent-Id: <instance>` on every request so that even unattributed decoy contacts name the agent.

## Notes
* Exceptions: return a generic tool error to the model rather than the honeypot details, so you don't reveal your traps.
* Memory: after a trigger, wipe the agent's memory of the encounter before any resumption.
* Multi-agent systems: give every agent its own `agent_id` and its own planted decoys; `cross_agent` flags then reveal sharing or collusion.
