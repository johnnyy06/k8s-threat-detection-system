# ml-ids — strat ML/IDS exploratoriu (Cap E)

Componentă **exploratorie**, paralelă și **aditivă** la sistemul principal determinist (Falco + Suricata
+ ELK + Talon). **NU îl înlocuiește** — citește aceleași date și scrie o a doua opinie într-un index
separat `security-ml-*`. Un RandomForest pe flow-uri Suricata (network); ML-ul se atașează la Suricata,
NU la Falco (Falco e syscall/host, rule-based; datasetele sunt network-flow).

## Două faze

### 1. Studiu offline (antrenare + evaluare)
- **Dataset-uri publice** CIC-IDS2017 + CIC-UNSW-NB15 → studiu de **domain shift** (within F1 0.96-0.997,
  cross-dataset colapsează la F1 ~0.0001 = modelul NU generalizează între medii). Vezi `DATASETS.md`, `RESULTS.md`.
- **Date proprii din cluster** → model **self-consistent** cu pipeline-ul live (features native Suricata EVE,
  fără domain shift). F1 **0.986** pe mediul propriu. → `models/rf_cluster.joblib`.
- Poanta Cap E: *„antrenează pe datele tale pentru deployment"* — model pe date proprii (0.986) vs transfer
  cross-env (0.0001).

| Script | Rol |
|---|---|
| `train_rf.py` | RF per-dataset public (`cicids2017\|cicunsw [binary\|multiclass\|both]`) |
| `cross_dataset.py` | studiu domain-shift (train pe unul, test pe celălalt) |
| `collect_cluster_data.py` | extrage + etichetează flow-uri Suricata din ES → `cluster_flows.csv` |
| `train_cluster_rf.py` | antrenează RF pe datele proprii → `models/rf_cluster.joblib` |

### 2. Inferență live (in-cluster) — `infer_live.py`
Serviciul de **serving**: puntea dintre modelul antrenat și traficul real. La fiecare rulare:
1. interoghează ES după flow-uri Suricata (`event_type=flow`) — **read-only** pe `security-*`;
2. extrage **exact** aceleași features ca la antrenare (importă `to_row` din `collect_cluster_data.py`)
   și le aliniază la coloanele modelului (`clf.feature_names_in_`);
3. scorează cu `rf_cluster.joblib` (ATTACK/BENIGN);
4. corelează pe `flow_id` cu alertele Suricata → câmpul `detection`
   (**both** / **ml_only** = detecție nouă / **rule_only** = ML miss / **quiet**);
5. scrie predicțiile în indexul **paralel `security-ml-*`** (upsert pe `flow_id`).

Două moduri: `--since/--until` (one-shot, demo/backfill) și `--watch --interval` (continuu).
`ES_URL` din env (implicit floating-IP pe laptop; `http://10.11.0.3:9200` intern în pod).

```bash
# one-shot de pe laptop (după ce rulezi un scenariu de atac):
./.venv/bin/python infer_live.py --since now-15m --until now
# continuu:
./.venv/bin/python infer_live.py --watch --interval 30
```

Vizualizare: **Kibana dashboard 05** (`thesis-ml-vs-deterministic`, data view `security-ml-*`) —
comparație determinist ↔ ML. Build: `cd ../dashboards/05-ml-comparison && python3 build.py`.

## Deployment in-cluster (varianta always-on)
Rulează ca **Deployment `ml-infer`** (ns `ml-ids`, node-2). Imagine `localhost/ml-infer:latest` construită
cu podman pe node-2 + sideload `microk8s ctr image import` (cluster fără registry). Runbook complet +
build/rollback: **`k8s/README.md`**.

## Fișiere
- `infer_live.py`, `security-ml-template.json` (mapping ES) — inferența live
- `Dockerfile`, `requirements-infer.txt`, `k8s/` — împachetare Deployment
- `models/` (gitignored `*.joblib`), `reports/` (PNG), `cluster_flows.csv` (gitignored), `RESULTS.md`, `DATASETS.md`

## Decizii de scope (importante)
- **NU Elastic ML** (licență ES Basic, `ml.available:false`) → extern, Python/sklearn.
- **scikit-learn fixat la 1.9.0** (versiunea cu care e serializat `rf_cluster.joblib`) — vezi `requirements-infer.txt`.
- ML = **strat exploratoriu** peste sistemul determinist; clasificarea ATTACK e robustă, sub-categoria
  `detection` (both/ml_only) e sensibilă la fereastra de corelare (decuplată via `--alert-window`).
