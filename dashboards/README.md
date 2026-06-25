# Kibana Dashboards — Thesis K8s Threat Detection

5 dashboards complementare, fiecare răspunzând la o întrebare distinctă pentru investigarea amenințărilor în clusterul K8s. Sursa de date pentru 01-04 este indexul unificat `security-*` cu schema ECS (Elastic Common Schema), populată de Logstash din webhook-uri Falco și fișierele EVE JSON Suricata. Dashboard 05 (ML, Cap E) folosește indexul paralel `security-ml-*`.

## Lista dashboard-urilor

| # | Folder | Slug Kibana | Răspunde la |
|---|---|---|---|
| 01 | [01-overview/](01-overview/) | `thesis-overview-security-posture` | "Care e starea securității în ultimele 24h?" |
| 02 | [02-mitre/](02-mitre/) | `thesis-mitre-attck-coverage` | "Care tehnici MITRE ATT&CK sunt acoperite de regulile mele?" |
| 03 | [03-cross-tool/](03-cross-tool/) | `thesis-cross-tool-correlation` | "Cum se completează Falco și Suricata reciproc?" |
| 04 | [04-per-scenario/](04-per-scenario/) | `thesis-per-scenario-investigation` | "Ce a detectat sistemul pentru un scenariu de atac specific?" |
| 05 | [05-ml-comparison/](05-ml-comparison/) | `thesis-ml-vs-deterministic` | "Ce aduce stratul ML (Cap E) față de detecția deterministă?" |

Acces direct: `${KIBANA_URL}/app/dashboards#/view/<slug>` (de pe laptop prin floating IP).

## Setup (înainte de prima rulare)

Build scripts citesc endpoints + UUID-uri din `.env` la repo root (gitignored). Copiază template-ul și completează valorile reale ale clusterului tău:

```bash
cp ../.env.example ../.env
# edit ../.env cu KIBANA_URL + KIBANA_DATA_VIEW_ID + KIBANA_DATA_VIEW_ECS_ID
```

Loader: [`_config.py`](_config.py) (Python, parsează .env shell-style, eroare clară la lipsă). Va eșua imediat cu instrucțiuni dacă valorile sunt placeholders (`00000000-...`).

## Dependențe (must-have)

Înainte ca dashboard-urile să funcționeze, pipeline-ul de date trebuie aliniat:

1. **Logstash conf ECS-enriched**: `elk/logstash/logstash-security.conf` cu stage-urile de enrichment Suricata + Falco + MITRE. Live pe node-4 systemd.
2. **Elasticsearch index template** `security-template`:
   - `index.mapping.total_fields.limit: 2000` (default 1000 e prea mic pentru schema ECS)
   - Pre-declarate ca `keyword` câmpurile ECS critice (`event.*`, `rule.*`, `threat.*`, `observer.*`, `source.*`, `destination.*`, `network.*`, `process.*`, `container.*`, `kubernetes.*`, `orchestrator.*`)
3. **Două data views**:
   - `security-*` (id `${KIBANA_DATA_VIEW_ID}`) — toate indecșii, folosit de panel-urile Lens cu agregări (KPIs, bars, area). TimeFieldName trebuie setat la `@timestamp`, altfel KPIs ignoră dashboard time range.
   - `security-ecs` (id `${KIBANA_DATA_VIEW_ECS_ID}`) — pattern cu exclusion list pentru indecșii pre-ECS (2026-05-01..22). Folosit de saved searches (sortare) și Dashboard 04 (control + runtime field `scenario`).

## Cum se (re)construiește un dashboard

Fiecare folder are propriul `build.py` care:
1. POST-uie fiecare panel ca obiect Lens (sau saved search) prin Saved Objects API
2. POST-uie dashboard-ul care le referă cu grid layout
3. Exportă rezultatul ca `dashboard.ndjson` (versionat în git)

```bash
cd dashboards/01-overview
python3 build.py
```

Idempotent — `?overwrite=true` pe fiecare POST. Run-uri repetate update-uiește panel-urile existente.

## Cum se importă într-o instanță Kibana proaspătă

```bash
# Pentru fiecare dashboard:
curl -X POST "${KIBANA_URL}/api/saved_objects/_import?overwrite=true" \
  -H 'kbn-xsrf: true' --form file=@01-overview/dashboard.ndjson
```

Sau via UI: Stack Management → Saved Objects → Import → selectează NDJSON.

## Pattern de build (Python via Kibana API)

Toate scripturile au aceeași structură:
- Helpers pentru column types (count_col, terms_col, date_hist_col, cardinality_col, filters_col)
- Helpers pentru panel types (make_metric, make_terms_bar, make_stacked_area, make_pie_filters, make_treemap, make_datatable, make_stacked_bar, make_line, make_saved_search)
- O listă `PANELS` cu definiția fiecărui panel + grid position (x, y, w, h)
- `build_dashboard()` care le asamblează cu referințe
- `export_ndjson()` pentru versionarea în git

**De ce Python + API** (în loc de NDJSON hand-crafted): Lens JSON este foarte verbos și fragil între versiuni Kibana. POST-ul individual prin API are validare server-side imediată — orice eroare apare la build time. Rebuild se face în secunde.

## Lessons learned (cross-dashboard)

1. **Câmpuri ECS lipsesc în indecșii pre-migrație** → saved searches eșuează la sort cu "No mapping found in order to sort on" pe shard-urile vechi. Soluție: data view dedicat `security-ecs` cu exclusion list explicit (`security-*,-security-2026.05.01,...,-security-2026.05.22`). ES NU suportă char class `[3-9]` în index patterns.
2. **Lens metric KPI cu customLabel duplicat**: dacă pui `title="X"` și pe panel și pe coloană (cu customLabel=True), apare duplicat în UI. Soluție: label gol pe coloană (`" "`).
3. **Data view fără `timeFieldName`**: KPI-uri ignoră dashboard time range, arată ALL-TIME. Setează `@timestamp` ca time field.
4. **KQL nu acceptă space escape în wildcard**: `SURICATA\ STREAM*` → eroare. Soluție: `SURICATA*` (fără escape).
5. **Options List Control pe câmp generic**: dropdown afișează toate valorile câmpului. Pentru a filtra (ex: doar `scenario_*`), creează un **runtime field** dedicat care extrage subset-ul dorit din câmpul original.
6. **Controls și data view-uri diferite**: dacă controlul filtrează pe field-ul X, toate panel-urile filtrate trebuie să folosească același data view în care X există. Altfel filtrul e ignorat tăcut.

## Mapping panel-uri → câmpuri ECS folosite

Pentru rapid lookup când vrei să modifici o regulă Falco și vrei să vezi unde apare în dashboards:

| Câmp ECS | Folosit în |
|---|---|
| `rule.name` | 01 (Top rules), 02 (data table), 04 (Top rules, event stream) |
| `event.severity` (numeric 0-7) | 01 (KPI Critical, Severity pie), 02 (KPI Critical), 04 (Severity pie) |
| `event.kind / category / module / dataset` | 01-04 (filtre implicite KPIs) |
| `threat.framework / technique.id / technique.name / tactic.name` | 02 (toate panel-urile) |
| `observer.product / hostname / vendor` | 01 (Events by node), 03 (Cross-tool timeline, Per-host × tool) |
| `kubernetes.namespace / pod.name` | 01 (Top namespaces), 02 (Top pods), 03 (Per-namespace), 04 (Pods involved) |
| `source.ip / destination.ip` | 01 (Top dests), 03 (Top dests, event stream), 04 (event stream) |
| `process.name / command_line` | 02 (Top processes), 04 (Processes involved, event stream) |
| `file.path` | 04 (event stream) |
| `tags : scenario_*` | 04 (runtime field `scenario` + control) |
