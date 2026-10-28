# Scoring methodology

## Control status
| Status | Value |
|---|---|
| Implemented | 1.0 |
| Partial | 0.5 |
| Not implemented | 0.0 |
| N/A / not assessed | excluded |

## Severity weights
Critical **4** · High **3** · Medium **2** · Low **1**

## Posture score
`score = Σ(weight × value) / Σ(weight)` over the assessed, in-scope controls, expressed as 0–100.

| Score | Maturity level |
|---|---|
| < 40 | L1 · Initial |
| 40–59 | L2 · Developing |
| 60–79 | L3 · Defined |
| 80–94 | L4 · Managed (recommended target) |
| ≥ 95 | L5 · Optimized |

## Scope
Choosing a reference architecture limits the assessment to controls tagged for that architecture plus
the universal (`*`) controls.

## Roadmap ranking
`risk = weight × (1 − value)`. Phase 1 (0–30 days) = Critical, Phase 2 (31–90) = High, Phase 3 (91–180) = Medium/Low.

## Framework coverage
For each framework requirement, coverage is the severity-weighted mean value of the in-scope blueprint controls mapped to it.
Covered ≥ 95% · Partial 50–94% · Gap < 50%. Function, control and theme averages are the unweighted mean of their requirements.

> Coverage reflects the **network domain only**. A "Covered" requirement means the network-side controls
> are in place, not that the whole requirement is satisfied organisation-wide.

## MITRE ATT&CK coverage
Each technique is linked to the blueprint controls that **mitigate or detect** it. Coverage uses the same weighted formula, so *Covered* means those controls are implemented. It does **not** mean the technique is fully prevented: ATT&CK techniques are usually addressed by several controls across network, endpoint and identity. Each technique is grouped under one primary tactic, although many techniques belong to several.
