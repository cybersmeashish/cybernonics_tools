# Contributing

1. `pip install -e ".[dev]"` then `pytest -q` and `python examples/demo_compromised_agent.py`.
2. New honeypot kinds go in `agent_honeypot/planter.py` (`PLANTERS`) with a default severity and a test.
3. Keep runtime dependencies at zero (stdlib only). Optional extras are fine.
4. Don't publish implementation details that make specific deployed decoys easier to identify.

Ideas welcome: Kubernetes/Helm chart, Terraform for the AWS reference deployment, MCP proxy, LLM-generated environment-specific decoys (with cross-model review), deterrence experiment harness.
