# Dashboard 01 — Overview / Security Posture

## Purpose

"Care e starea securității în ultimele 24h?" — top-level surveillance pentru un overview rapid: câte alerte, ce regulile cele mai frecvente, distribuție pe noduri și namespace-uri, vizualizare MITRE.

## URL & data view

- Kibana URL: <${KIBANA_URL}/app/dashboards#/view/thesis-overview-security-posture>
- Data view: `security-*` (id `${KIBANA_DATA_VIEW_ID}`)
- Time range default: Last 24h
- Refresh: pauzat (apasă manual pentru screenshots clean)

## Panels (13)

| # | Panel | Type | Filter (KQL) | Câmpuri |
|---|-------|------|--------------|---------|
| 1 | Total events | Metric KPI | — | `count(*)` |
| 2 | Falco alerts | Metric KPI | `tags : "falco"` | `count(*)` |
| 3 | Suricata events | Metric KPI | `tags : "suricata"` | `count(*)` |
| 4 | Critical+High (sev≤3) | Metric KPI | `event.severity <= 3` | `count(*)` |
| 5 | Event timeline — by tool | Stacked area | — | `@timestamp` × `observer.product` |
| 6 | Top Falco rules | Bar horizontal | `tags : "falco"` | `rule.name` × count |
| 7 | Top Suricata signatures | Bar horizontal | `tags : "suricata" and event_type : "alert" and not rule.name : SURICATA*` | `rule.name` × count |
| 8 | Suricata events by type | Donut | `tags : "suricata"` | `event_type.keyword` × count |
| 9 | Top Suricata destinations | Bar horizontal | `tags : "suricata"` | `destination.ip` × count |
| 10 | Severity distribution | Pie (filters) | — | KQL buckets: `event.severity <= 2` / `: 3` / `: 4` / `: 5` / `: 6` / `: 7` |
| 11 | Events by node | Donut | — | `observer.hostname` × count |
| 12 | MITRE ATT&CK coverage | Treemap | `threat.framework : "MITRE ATT&CK"` | `threat.tactic.name` → `threat.technique.name` × count |
| 13 | Top Kubernetes namespaces | Bar horizontal | `tags : "falco"` | `kubernetes.namespace` × count |

## Key insights (narativ pentru defense)

- **Volum events**: ordinul a 70k-100k events/24h (preponderent Suricata flow telemetry, ~30% Falco). Asta arată că platforma capturează telemetrie densă chiar și fără atacuri active.
- **Top Falco rules**: dominat de `K8S_THREAT: Kubernetes Secret Access from Pod` și `Sensitive File Read in Container` — preponderent FP-uri din Prometheus/kube-state-metrics care își citesc propriul SA token. Asta e fenomenul de **alert fatigue** documentat în literatura SecOps și e material pentru Cap 6 Limitări.
- **Top Suricata signatures**: filtrul `not rule.name : SURICATA*` elimină regulile builtin de protocol anomaly (STREAM, HTTP parse errors). Rămân doar regulile cu prefix `ET *` (Emerging Threats community ruleset) — real threat signal.
- **Severity distribution**: predominant Warning + Notice (90%+). Critical este < 1% — corect pentru un cluster fără atacuri active, dar arată că regulile noastre custom diferențiază corect priority levels.
- **MITRE coverage**: vezi Credential Access dominant (~91%) din cauza background-ului Prometheus. Restul tehnicilor (Discovery, Execution, Privilege Escalation, etc.) reprezintă scenariile de atac validate.
- **Top namespaces**: `observability` (Prometheus stack) și `attack-target` (pod-urile noastre de atac) — confirmă că Falco vede contextul k8s corect.

## How to (re)build from scratch

```bash
cd dashboards/01-overview
python3 build.py
```

Va POST-ui 13 panel-uri Lens + dashboard-ul la Kibana (overwrite=true) și va re-exporta `dashboard.ndjson`.

## Lessons & gotchas (din build-ul real)

1. **`security-*` data view inițial fără `timeFieldName`** → KPIs ignorau `Last 24h` time range și arătau ALL-TIME (4.9M în loc de 74k). Fix: PATCH la data view setând `timeFieldName: "@timestamp"`. Apoi refresh dashboard.

2. **KPI label duplicat**: la primul build, panelele Metric afișau atât panel title cât și column label cu același text (e.g. "Falco alerts" de 2 ori). Fix în `build.py`: column label = `" "` (spațiu) cu `customLabel: True` → ascunde subtitlu, rămâne doar panel title.

3. **Top Suricata signatures poluat de noise**: regulile native `SURICATA STREAM 3way handshake wrong seq wrong ack`, `SURICATA STREAM Packet with invalid timestamp` reprezintă protocol anomalies, nu threat detection. Sunt baseline TCP noise (~70% din alertele Suricata raw). Filtru: `not rule.name : SURICATA*`.

4. **KQL escape bug**: prima încercare a fost `not rule.name : SURICATA\ STREAM*` (escape space) — eroare "Expected AND, OR, end of input but `\` found". KQL nu suportă escape de space în wildcards. Soluție: `SURICATA*` (fără space).

5. **Severity ca numere (0-7) e neprietenos** pentru viewer. Soluția: bucket-uri KQL labeled (`Emergency/Alert/Critical`, `Error`, `Warning`, `Notice`, `Informational`, `Debug`) prin column type `filters` în Lens.

## Screenshots

Director: [`screenshots/`](screenshots/)

- `overview-full.png` — dashboard complet la Last 7 days, după re-run scenarii
- `overview-mitre-tooltip.png` — hover pe treemap MITRE arată percentages
- `overview-drilldown.png` — click pe Top 1 Falco rule → vezi filtru aplicat în toate panel-urile (cross-filtering)
