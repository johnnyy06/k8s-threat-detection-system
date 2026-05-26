# Dashboard 03 — Cross-Tool Correlation

## Purpose

"Cum se completează Falco și Suricata reciproc?" — justifică direct alegerea arhitecturală **defense-in-depth** a sistemului (2 tool-uri ≠ duplicare, ci complementaritate). Demonstrează că Falco vede runtime/syscalls și Suricata vede network packets — aceeași infrastructură văzută din 2 unghiuri distincte.

**Insight cheie:** node-2 e singurul nod cu vizibilitate cross-tool real, pentru că Suricata rulează ca systemd doar pe node-2, în timp ce Falco rulează ca DaemonSet pe toate cele 4 noduri.

## URL & data view

- Kibana URL: <${KIBANA_URL}/app/dashboards#/view/thesis-cross-tool-correlation>
- Data view: `security-*` pentru panel-urile Lens (KPIs, bars, area); `security-ecs` pentru saved search (event stream) — necesar pentru sortare
- Time range default: Last 24h
- Filtru implicit: niciunul (default arată toate evenimentele)

## Panels (10)

| # | Panel | Type | Filter (KQL) | Câmpuri |
|---|-------|------|--------------|---------|
| 1 | Total events (both tools) | Metric KPI | — | `count(*)` |
| 2 | Falco events | Metric KPI | `tags : "falco"` | `count(*)` |
| 3 | Suricata events | Metric KPI | `tags : "suricata"` | `count(*)` |
| 4 | Critical+High (sev≤3) | Metric KPI | `event.severity <= 3` | `count(*)` |
| 5 | Cross-tool timeline | Stacked area | — | `@timestamp` × `observer.product` |
| 6 | Events per host × tool (KEY) | Stacked bar horizontal | — | `observer.hostname` × `observer.product` × count |
| 7 | Top Suricata destinations | Bar horizontal | `tags : "suricata"` | `destination.ip` × count |
| 8 | Combined event stream | Saved search (Discover view) | — | `@timestamp`, `observer.product`, `event.severity`, `rule.name`, `kubernetes.namespace`, `kubernetes.pod.name`, `process.name`, `source.ip`, `destination.ip` |
| 9 | Events per K8s namespace | Bar horizontal | `tags : "falco" and kubernetes.namespace : *` | `kubernetes.namespace` × count |
| 10 | Top Falco-affected pods | Bar horizontal | `tags : "falco"` | `kubernetes.pod.name` × count |

## Key insights (narativ pentru defense)

- **Panel 6 (Events per host × tool)** este vedeta:
  - `node-2`: bar cu 2 culori (Falco ~12 + Suricata ~44k) — singura locație cu cross-tool real
  - `node-1`, `node-3`, `node-4`: doar Falco bar — pe acestea Suricata e blind
  - Demonstrează vizual realitatea arhitecturală a sistemului
- **Cross-tool timeline overlay**: ambele tool-uri văd cluster-ul SIMULTAN, dar pe layere diferite. Suricata domină volumetric (flow telemetry), Falco e mai sparse dar punctual când fire rules.
- **Combined event stream**: pe fiecare rând vezi `observer.product` (Falco / Suricata) + câmpurile specifice. Falco events au `kubernetes.pod.name` și `process.name`; Suricata events au `source.ip`, `destination.ip`. Demonstrează cele 2 vederi complementare side-by-side.
- **Per-namespace (Falco only)**: Suricata nu populează `kubernetes.namespace` (e blind la K8s context). Demonstrează vizual limitarea structurală — pentru K8s-aware investigation, Falco e necesar; pentru network-level visibility, Suricata.

## How to (re)build from scratch

```bash
cd dashboards/03-cross-tool
python3 build.py
```

Scriptul rulează `ensure_ecs_data_view()` care creează/actualizează data view-ul `security-ecs` (id `${KIBANA_DATA_VIEW_ECS_ID}`) cu exclusion list pentru indecșii pre-ECS. Apoi construiește 10 panel-uri (9 Lens + 1 saved search) + dashboard.

## Lessons & gotchas

1. **ES NU suportă char class `[3-9]` în index patterns**. Prima versiune a data view-ului `security-ecs` avea pattern `security-2026.05.2[3-9]*` → match-uia 0 indecși → dashboard arăta "no results". Soluția funcțională: exclusion list explicit (`security-*,-security-2026.05.01,...,-security-2026.05.22`).

2. **Saved searches sortează la nivel de shard ÎNAINTE să aplice filtre**. Dacă vreun shard nu are field-ul (cazul rule.name, source.ip în indecșii pre-ECS), eroare "No mapping found for X in order to sort on" la fiecare încercare de sort. Lens visualizations nu suferă (agregările skip silent shard-urile lipsă). Soluție: data view dedicat care exclude indecșii fără ECS schema.

3. **Confuzie de data view-uri**: Lens panels folosesc `security-*` (volumetric complete), saved search folosește `security-ecs` (sortable). Acest mix e ok atâta timp cât KPIs nu trebuie să fie consistente cu event stream (KPIs arată "total events" cumulat, event stream arată detalii recente sortate).

4. **stacked_bar series type**: pentru bar horizontal stacked, `seriesType` trebuie să fie `bar_horizontal_stacked`, nu `bar_horizontal`. Acelaşi cu `bar_stacked` pentru orientare verticală.

## Screenshots

Director: [`screenshots/`](screenshots/)

- `cross-tool-full.png` — dashboard complet (rândul cu host×tool fundamental)
- `cross-tool-per-host.png` — close-up pe panel 6 cu node-2 stack vizibil
- `cross-tool-event-stream-sorted.png` — event stream sortat alfabetic pe `rule.name` (demo cross-tool inter-mix)
- `cross-tool-namespace-only-falco.png` — panel 9 cu doar Falco events (Suricata absent)
