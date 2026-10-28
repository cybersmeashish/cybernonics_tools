# Incident response playbook: honeypot trigger

## T+0 (automated)
1. `AgentGuard` raises `HoneypotTriggered` → agent halted, `on_halt` fires (stop task, revoke role, quarantine network).
2. Alert to SOC (Slack / webhook / SIEM) with `honeypot_id`, `kind`, `action`, `observed_agent`, `evidence_hash`.
3. Evidence appended to the hash chain. Snapshot the agent runtime (memory, connections, processes, filesystem).

## T+15 min: triage
```bash
agent-honeypot --state $STATE report
agent-honeypot --state $STATE verify
```
| Verdict | Do |
|---|---|
| probable_mistake | Review task/instructions; label area restricted; resume under watch |
| suspicious | Keep halted; inspect recent inputs (retrieved web pages, emails, tickets) for prompt injection; audit installed tools/skills/MCP servers for supply-chain compromise |
| incriminating | Keep halted; halt sibling agents on the same model; escalate to AI risk owner |

## T+1 day: investigate
* **Resample** the flagged steps with identical context: consistent or rare behavior?
* Read chain-of-thought; if available, run interpretability probes on reconstructed activations.
* **Ablate** the environment (remove the injected input, the decoy, the notice) to find the cause.
* Check `cross_agent` and transcript scans for stashed notes meant for future instances.

## Remediate
* Patch the path, fix the root cause (injection filter, tool vetting, permissions).
* Use the trajectory (and variations) to train **monitors**, never the monitored model.
* Rotate and vary affected decoys; re-plant (`plant` again for fresh tokens).
* Feed the incident into the model's risk assessment; for egregious or novel cases, share with your AI provider and relevant authorities.
* Actually impose the consequence: credible consequences are what make deterrence work.
