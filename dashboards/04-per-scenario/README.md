# Dashboard 04 — Per-Attack-Scenario Investigation

## Purpose

"Ce a detectat sistemul pentru un scenariu de atac specific?" — dashboard parametrizat cu **Options List Control** pe câmpul `scenario` (runtime field). User pică scenariul din dropdown → toate panel-urile filtrează automat la acel scenariu. Cel mai valoros panel pentru demo interactiv la apărarea tezei.

## URL & data view

- Kibana URL: <${KIBANA_URL}/app/dashboards#/view/thesis-per-scenario-investigation>
- Data view: `security-ecs` (id `${KIBANA_DATA_VIEW_ECS_ID}`) pentru TOATE panel-urile (necesar pentru ca controlul pe runtime field `scenario` să propage filtrul în toate panel-urile)
- Time range default: Last 7 days

## Control

| Element | Detalii |
|---|---|
| Tip | Options List Control |
| Câmp | `scenario` — **runtime field** care extrage doar tag-urile `scenario_NN` din array-ul `tags[]` |
| Mode | Single select |
| Default | Niciun scenariu selectat → arată toate (mod overview) |
| Filtru aplicat | `scenario : "scenario_NN"` global, propagat în toate panel-urile |

Script-ul runtime field (Painless):
```painless
for (def t : doc["tags"]) {
    if (t.startsWith("scenario_")) emit(t);
}
```

## Panels (10)

| # | Panel | Type | Query implicit | Câmpuri |
|---|-------|------|----------------|---------|
| 1 | Detections in scenario | Metric KPI | `tags : scenario_*` | `count(*)` |
| 2 | Unique rules fired | Metric KPI cardinality | `tags : scenario_*` | `unique_count(rule.name)` |
| 3 | Critical+High (sev≤3) | Metric KPI | `tags : scenario_* and event.severity <= 3` | `count(*)` |
| 4 | Affected pods | Metric KPI cardinality | `tags : scenario_*` | `unique_count(kubernetes.pod.name)` |
| 5 | Detections over time | Line chart | `tags : scenario_*` | `@timestamp` × count |
| 6 | Rules fired in scenario | Bar horizontal (size 15) | `tags : scenario_*` | `rule.name` × count |
| 7 | Severity distribution | Pie (filters) | KQL bucket-uri pe `event.severity` | per bucket count |
| 8 | Event stream | Saved search | `tags : scenario_*` | @timestamp, rule.name, event.severity, kubernetes.pod.name, process.name, process.command_line, file.path, destination.ip |
| 9 | Pods involved | Bar horizontal (size 8) | `tags : scenario_*` | `kubernetes.pod.name` × count |
| 10 | Processes involved | Bar horizontal (size 8) | `tags : scenario_*` | `process.name` × count |

Toate panel-urile au filtrul implicit `tags : scenario_*` astfel încât în mod "no selection" se văd toate scenariile cumulat, NU toate evenimentele (inclusiv background).

## Scenariile disponibile (11 total — tag-uri scenario_NN)

Scenariile 01-08 au tag-uri puse direct de regulile Falco custom K8S_THREAT.
Scenariile 09-11 NU au reguli custom dedicate — tag-urile sunt inferate de
Logstash (Stage 4) pe baza unor amprente: pod name pattern pentru 09/10,
respectiv `command_line: *Authorization*Bearer*` pentru 11.

| Scenario | Tag | Discriminator | Top rule / signature |
|---|---|---|---|
| 01 Container Escape | `scenario_01` | regulă Falco custom | Container Escape - Nsenter/Chroot, Sensitive Mount Access |
| 02 Crypto Mining | `scenario_02` | regulă Falco custom | Crypto Mining Binary, Pool Connection |
| 03 Reverse Shell | `scenario_03` | regulă Falco custom | Reverse Shell Command Pattern, Netcat Listener |
| 04 Sensitive File | `scenario_04` | regulă Falco custom | Sensitive File Read, K8S Secret Access (dominat de FP-uri Prometheus) |
| 05 Network Scanning | `scenario_05` | regulă Falco custom | Network Scanning Tool |
| 06 Privilege Escalation | `scenario_06` | regulă Falco custom | Privilege Escalation Setuid/Setgid, Sudo Usage |
| 07 Data Exfiltration | `scenario_07` | regulă Falco custom | DNS Exfiltration Suspicion, Transfer Tool |
| 08 Malicious Deployment | `scenario_08` | regulă Falco custom | Binary Downloaded&Executed, Package Manager |
| 09 OWASP ZAP | `scenario_09` | Logstash: pod name `zap-scan-*` | semnături Suricata ET WEB / SCAN |
| 10 kube-hunter | `scenario_10` | Logstash: pod name `kube-hunter-*` | Network Service Discovery + K8s API access |
| 11 Lateral Movement | `scenario_11` | Logstash: cmdline `Authorization*Bearer` | Contact K8S API Server From Container (cu SA token) |

## Cum se rulează un scenariu (pentru a popula dashboard-ul cu date noi)

```bash
cd attack-scenarios
./03-reverse-shell/attack.sh   # ~1-2 min, autonom (executes + verifies)
```

După ~30s evenimentele apar în ES → dashboard se refresh-uiește (apasă Refresh sus-dreapta).

## Key insights (narativ pentru defense)

- **Demo interactiv**: comisar poate cere "arată scenariul de container escape" → tu pici `scenario_01` din dropdown live, toate panel-urile fac transition fluid
- **Per-scenario evidence auto-generated**: fiecare scenariu are dovada lui (rules + pods + processes + raw event stream) fără query manual
- **Differentiator unique**: replaces manual investigation in Discover via KQL (`tags : "scenario_05" and @timestamp > now-1h`)
- **Scenario_04 outlier (90k vs <50)**: ilustrează cum o regulă bine-țintită poate fi inundată de background events legitime (Prometheus reading SA token este tag-uit cu `scenario_04` pentru că regula `K8S_THREAT: Sensitive File Read` are tag-ul scenariu). Material pentru Cap 6 Limitări.

## How to (re)build from scratch

```bash
cd dashboards/04-per-scenario
python3 build.py
```

Scriptul rulează:
1. `ensure_scenario_runtime_field()` — adaugă runtime field `scenario` la data view `security-ecs` (idempotent)
2. Construiește 10 panel-uri + dashboard cu `controlGroupInput` configurat
3. Exportă `dashboard.ndjson`

## Lessons & gotchas

1. **Options List Control pe câmp generic**: prima versiune a folosit Options List pe câmpul `tags` direct. Dropdown afișa TOATE tag-urile (T1552, falco, custom_rule, mitre_*, scenario_*, etc.) — zeci de opțiuni. Soluție: runtime field `scenario` care extrage doar `scenario_*` din array-ul tags. Dropdown afișează acum doar cele 11 scenarii.

2. **Controls și data view consistency**: dacă controlul filtrează pe `scenario` (runtime field în data view A), panel-urile filtrate trebuie să folosească același data view A. Prima versiune avea controlul pe security-ecs și panel-urile pe security-*. Filtrul aplicat de control nu propaga la panel-uri (silent fail — fără date filtrare). Fix: schimbat TOATE panel-urile la security-ecs.

3. **Runtime field PUT vs POST**: Kibana API pentru runtime field e `PUT /api/data_views/data_view/{id}/runtime_field` (nu POST). PUT e idempotent — re-run scriptul actualizează scriptul Painless dacă diferă.

4. **Painless script sintaxă**: `for (def t : doc["tags"]) { ... emit(t) ... }` funcționează. `doc.tags.value` returnează doar primul element. Pentru array iteration, folosește `for ... : doc[field]`.

5. **Default time range Last 7d**: scenariile au fost rulate o singură dată (2026-05-23). Pentru a vedea date, time range trebuie să acopere acea zi. Last 24h ar exclude scenariile (azi e 2026-05-26+). Setat default la Last 7d.

## Screenshots

Director: [`screenshots/`](screenshots/)

- `per-scenario-control-open.png` — dropdown deschis cu cele 11 scenarii vizibile
- `per-scenario-04-selected.png` — scenario_04 selectat (dominat de Sensitive File Read)
- `per-scenario-03-reverse-shell.png` — scenario_03 selectat (vezi reverse shell + netcat patterns)
- `per-scenario-09-zap.png` — scenario_09 selectat (ZAP DAST scan, Suricata-driven)
- `per-scenario-10-kube-hunter.png` — scenario_10 selectat (kube-hunter recon)
- `per-scenario-11-lateral-movement.png` — scenario_11 selectat (Bearer token reuse pivot)
- `per-scenario-event-stream-detail.png` — event stream pentru un scenariu specific
