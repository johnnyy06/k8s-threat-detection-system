# Dashboard 05 — ML vs Deterministic Detection

Slug Kibana: `thesis-ml-vs-deterministic`
Acces: `${KIBANA_URL}/app/dashboards#/view/thesis-ml-vs-deterministic`

Răspunde la: **"Ce aduce în plus stratul ML (exploratoriu, Cap E) față de detecția deterministă pe semnături?"**

## Sursă de date

Index **paralel** `security-ml-*` (NU `security-*`), populat de [`ml-ids/infer_live.py`](../../ml-ids/infer_live.py):
RandomForest `rf_cluster.joblib` scorează fiecare flow Suricata (features native EVE, antrenat pe
datele proprii ale clusterului = fără domain shift) și scrie predicția. Fiecare doc e îmbogățit la
scorare cu corelarea pe `flow_id` față de alertele Suricata din `security-*`, în câmpul `detection`:

| `detection` | Înseamnă |
|---|---|
| `both` | ML ATTACK + a tras o semnătură Suricata (acord) |
| `ml_only` | ML ATTACK, nicio semnătură Suricata — **candidat detecție nouă / anomalie** |
| `rule_only` | semnătură Suricata, ML BENIGN — ML miss / semnătură pe flux benign |
| `quiet` | ambele tăcute (trafic normal) |

Comparația e single-index (Kibana nu face JOIN ușor). **Limitare onestă:** comparația e pe flow-urile
SCORATE (`event_type=flow`); o alertă Suricata fără un flow event scorat în fereastră nu apare.

## Panels (9)

1-4. KPI: total flow-uri scorate / ML ATTACK / cu semnătură Suricata / acord (both).
5. **Comparație determinist↔ML** (cele 4 celule) — panelul cheie.
6. Detecție în timp (stacked area pe `detection`).
7. `ml_only` — top `dest_port` (candidați detecție nouă ratați de semnături).
8. ML ATTACK — top `dest_ip`.
9. Saved search: fluxurile `ml_only` pentru investigație.

## (Re)build

```bash
cd dashboards/05-ml-comparison && python3 build.py
```
Necesită `.env` la repo root (KIBANA_URL) + index `security-ml-*` populat (rulează întâi
`ml-ids/infer_live.py`). Build-ul creează data view-ul `security-ml` (id `thesis-ml-security-ml`)
idempotent.
