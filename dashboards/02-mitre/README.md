# Dashboard 02 — MITRE ATT&CK Coverage

## Purpose

"Care tehnici MITRE ATT&CK sunt acoperite de regulile mele și cu ce intensitate?" — vizualizare cap-coadă a acoperirii MITRE pentru a demonstra mapping-ul detect ↔ framework. Diferențiator vs SIEM-uri vanilla — folosim direct `threat.tactic.*` / `threat.technique.*` (ECS canonical), populate din tagurile Falco `T1xxx` / `mitre_xxx` via Logstash ruby filter.

## URL & data view

- Kibana URL: <${KIBANA_URL}/app/dashboards#/view/thesis-mitre-attck-coverage>
- Data view: `security-*` (id `${KIBANA_DATA_VIEW_ID}`)
- Time range default: Last 7 days (MITRE distribuția e mai informativă peste săptămână)
- Filtru global implicit: `threat.framework : "MITRE ATT&CK"`

## Panels (11)

| # | Panel | Type | Filter (KQL) | Câmpuri |
|---|-------|------|--------------|---------|
| 1 | MITRE-tagged events | Metric KPI | `threat.framework : "MITRE ATT&CK"` | `count(*)` |
| 2 | Unique techniques | Metric KPI (cardinality) | `threat.framework : "MITRE ATT&CK"` | `unique_count(threat.technique.id)` |
| 3 | Unique tactics | Metric KPI (cardinality) | `threat.framework : "MITRE ATT&CK"` | `unique_count(threat.tactic.id)` |
| 4 | Critical+High MITRE (sev≤3) | Metric KPI | `threat.framework : "MITRE ATT&CK" and event.severity <= 3` | `count(*)` |
| 5 | Tactic timeline | Stacked area | MITRE | `@timestamp` × `threat.tactic.name` |
| 6 | Top tactics | Bar horizontal | MITRE | `threat.tactic.name` × count |
| 7 | Top techniques | Bar horizontal | MITRE | `threat.technique.name` × count |
| 8 | MITRE coverage matrix | Treemap | MITRE | `threat.tactic.name` → `threat.technique.name` × count |
| 9 | Technique → Falco rule mapping | Data table | MITRE | `threat.technique.name` × `threat.technique.id` × `rule.name` × count |
| 10 | Top pods with MITRE detections | Bar horizontal (size 5) | MITRE | `kubernetes.pod.name` × count |
| 11 | Top processes triggering MITRE rules | Bar horizontal (size 5) | MITRE | `process.name` × count |

## Key insights (narativ pentru defense)

- **77k MITRE-tagged events / 7 zile / 11 tehnici / 6 tactici** — acoperire respectabilă pentru un set de reguli custom + default Falco.
- **Tactic timeline**: arată clar baseline-ul steady (Credential Access dominant din Prometheus) + spike-uri scurte (Discovery / Execution când s-au rulat scenariile). Ilustrează cum un atac apare ca anomalie temporală peste background.
- **MITRE coverage treemap**: vezi vizual distribuția. **Credential Access 91%** e dominat de background (Prometheus + kube-state-metrics citesc SA tokens = T1552 Unsecured Credentials). Restul tehnicilor reprezintă atacuri reale.
- **Panel 9 — Technique → Falco rule mapping** e cel mai puternic panel al întregului set:
  - T1611 Escape to Host: 2 reguli complementare (`Container Escape - Nsenter/Chroot Usage` + `Container Escape - Sensitive Mount Access`) — **defense in depth** vizibil
  - T1059 Command Interpreter: 4 reguli (Reverse Shell pattern, STDOUT redirect, Netcat Listener, Netcat RCE) — multiple detection angles
  - T1048 Exfiltration: 2 vectori (DNS + Transfer Tool)
  - Demonstrează că mai multe reguli contribuie la aceeași tehnică = robustețe.
- **Top pods**: prometheus-server (67k) > kube-state-metrics (7k) > attack-pod (~zecimi). Background noise face 99% din volum, atacurile sunt anomalii.
- **Top processes**: `prometheus`, `kube-state-metr` (truncat la 16 chars de Falco), apoi `nmap`, `nc`, `nslookup` — atac tools real vizibile alături de procese legitime.

## How to (re)build from scratch

```bash
cd dashboards/02-mitre
python3 build.py
```

Va POST-ui 11 panel-uri (4 KPI + 4 bars + treemap + datatable + 1 stacked area) + dashboard + va exporta `dashboard.ndjson`.

## Lessons & gotchas

1. **Tehnici lipsă în technique_map**: prima versiune a Logstash ruby-filter mapping avea doar 10 tehnici (cele din regulile noastre custom). Default Falco rules au și ele tag-uri MITRE (e.g. `Read sensitive file untrusted` are T1557.002 + T1555). Acestea apăreau ca ID-uri raw în treemap. Fix: extins technique_map în `elk/logstash/logstash-security.conf` la 35 tehnici (custom + maturity_stable Falco defaults). Plus `_update_by_query` pe indexul curent pentru a backfill numele.

2. **KPI sub-label**: panel-urile cardinality afișau default "Unique count of threat.technique.id" sub titlu (redundant cu panel title). Fix la fel ca Dashboard 01: `customLabel: True` cu label ` ` (spațiu).

3. **Cardinality aggregation needs `params.emptyAsNull`**: fără asta, Lens uneori returnează 0 pe shard-uri fără docs vs `null` (afișat în UI ca "-"). Cu emptyAsNull: True, comportament uniform.

4. **Data table column ordering**: Lens datatable sortează coloanele după ordinea din `columnOrder`. Grupurile (terms) trebuie să vină ÎNAINTEA metrici (count) altfel agregarea e wrong (count se aplică la nivel de bucket greșit).

5. **Top N=10 cu date sparse**: pentru pods/processes filtered pe MITRE, doar 3-4 valori au date semnificative. Restul apăreau ca bar-uri goale (e.g. calico-node-*). Redus la `size: 5` pentru claritate.

## Screenshots

Director: [`screenshots/`](screenshots/)

- `mitre-full.png` — dashboard complet, vizibil treemap-ul mare
- `mitre-treemap-tooltip.png` — hover pe treemap arată percentages
- `mitre-rule-mapping-table.png` — tabel zoom pentru Cap D evidenta
- `mitre-tactic-timeline.png` — timeline cu vizibil baseline + spike-uri scenarii
