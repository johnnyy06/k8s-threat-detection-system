# Rezultate — componentă ML (Random Forest pe dataset-uri IDS)

Componentă **exploratorie** (Cap E – perspective). Soluția principală a proiectului rămâne
**rule-based** (Falco + Suricata + ELK); ML-ul e adăugat ca extensie/experiment, NU înlocuiește detecția deterministă.

## Setup
- **Date:** CIC-IDS2017 (2.83M flow-uri, 78 features CICFlowMeter) + CIC-UNSW-NB15 (448k flow-uri, 76 features). Vezi [DATASETS.md](DATASETS.md).
- **Model:** `RandomForestClassifier(n_estimators=100, class_weight="balanced")`, split stratificat 70/30.
- **Preprocesare:** Inf→NaN→drop (problema cunoscută CIC-IDS2017: ~2.9k rânduri cu NaN/Inf în `Flow Bytes/s`/`Flow Packets/s`); strip whitespace coloane; downcast float32 (memorie); fix mojibake label.
- **Cod:** `train_rf.py` (per-dataset), `cross_dataset.py` (domain shift). Reproductibil cu `requirements.txt`.

## 1. Rezultate per-dataset

| Dataset | Mod | Accuracy | F1 (weighted) | F1 (macro) | ROC-AUC |
|---|---|---|---|---|---|
| CIC-IDS2017 | binary | 0.9990 | 0.9990 | 0.9985 | 0.9998 |
| CIC-IDS2017 | multiclass (15 clase) | 0.9985 | 0.9985 | 0.868 | — |
| CIC-UNSW-NB15 | binary | 0.9827 | 0.9830 | 0.9738 | 0.9955 |
| CIC-UNSW-NB15 | multiclass (10 clase) | 0.9307 | 0.9327 | 0.626 | — |

**Interpretare:**
- **Binary (atac vs benign) = foarte bun pe ambele** (F1 atac 0.997 / 0.958) — RF separă eficient, relevant pentru reducerea FP.
- **CIC-UNSW e constant mai greu** decât CIC-IDS2017 (atacuri subtile: Analysis, Backdoor, Shellcode, Worms) — consistent cu literatura.
- **Clasele rare suferă** (macro << weighted): pe CIC-IDS2017 — XSS F1 0.37, SQLi 0.44, Bot 0.78 (din cauza dezechilibrului: Heartbleed 11 rânduri, SQLi 21, Infiltration 36); pe CIC-UNSW — Analysis 0.39, Shellcode 0.41, Worms 0.44. **Limitare = dezechilibru de clase.**

Ploturi (confusion matrix + feature importance) în `reports/`.

## 2. Studiu domain shift (cross-dataset) — contribuție originală

Antrenat pe un dataset, testat pe celălalt (binary, **74 features comune** armonizate între cele două versiuni CICFlowMeter):

| Experiment | Accuracy | F1 (attack) |
|---|---|---|
| IDS2017 → IDS2017 (within) | 0.9988 | **0.9970** |
| UNSW → UNSW (within) | 0.9827 | **0.9583** |
| **IDS2017 → UNSW (cross)** | 0.8000 | **0.0001** |
| **UNSW → IDS2017 (cross)** | 0.5787 | **0.1214** |

**Concluzie (esențială pentru Cap E):** un model care atinge **F1 ~0.96–0.997 pe propriul dataset se prăbușește la ~0.0001–0.12 pe alt dataset**. La IDS2017→UNSW modelul clasifică aproape totul ca BENIGN (recall atac ~0). Deci **modelul NU generalizează între medii/distribuții diferite de trafic = domain shift**, cea mai citată limitare a modelelor ML-IDS antrenate pe dataset-uri publice.

## 3. Implicații pentru integrarea în pipeline (Cap E / perspective)

- Un RF antrenat pe un dataset public **NU poate fi pus direct** să reducă FP-urile pe traficul clusterului — ar suferi exact acest domain shift.
- Pentru o integrare live reală ar fi necesar: (a) **feature alignment** — rularea CICFlowMeter și pe traficul propriu (Suricata EVE are alt set de features), și (b) **antrenare/fine-tuning pe date din mediul propriu** (alerte etichetate TP/FP).
- Arhitectural: **2 pipeline-uri** — unul determinist (rule-based, soluția principală) și unul augmentat ML (scoring RF într-un index paralel) — pentru comparație. Demonstrat conceptual; rămâne ca direcție de implementare.

## 4. Model pe date PROPRII din cluster (PoC — fără domain shift)

Pentru a evita domain shift-ul, am antrenat un RF separat pe **flow-uri Suricata din clusterul propriu**,
etichetate pe bază de ground-truth (scenarii de atac controlate). Cod: `collect_cluster_data.py` (extracție din
ES + labeling pe IP atacator) + `train_cluster_rf.py`. Features = **native Suricata EVE** (~20, one-hot → 32),
deci self-consistent cu pipeline-ul live (NU CICFlowMeter).

**Metodologie de colectare (curată):** benign-ul colectat dintr-o fereastră **liniștită de 12h** (peste noapte),
ÎNAINTE de a rula atacuri → separare temporală, fără contaminare de etichetă. (Capcană întâlnită: colectarea
benign pe o fereastră care includea atacuri = scan-uri etichetate greșit benign; de aceea benign-ul se ia dintr-o
fereastră fără atacuri.) Atacurile rulate separat, în ferestre controlate, etichetate pe IP-ul atacatorului.

**Topologie de senzori (finding-cheie):** pentru ca Suricata să prindă un atac, **fie atacatorul, fie ținta
trebuie să fie pe un nod cu senzor** (node-2/node-3; NU node-1/node-4). De aceea atacatorii au fost mutați pe **node-2**:
- **attack-pod pe node-2 → 314 flow-uri** (vs doar **49 când era pe node-4** fără senzor — plasarea contează enorm)
- **ZAP pe node-2 → DVWA(node-3) → 144 flow-uri** (inter-nod, sensor-near-target)
- **kube-hunter → 0** indiferent de nod (recon spre API node-1 peste TLS + raw sockets = fără flow events capturabile)
- Dataset final (`cluster_flows.csv`, 27 coloane = 23 features EVE + 4 metadata): **18.049 BENIGN / 458 ATTACK**
  (~2.4%, dezechilibru realist). Pe noduri — ATTACK: node-2 = 233, node-3 = 225; BENIGN: node-2 = 11.724, node-3 = 6.325.

**Rezultate (RF n_estimators=300, class_weight=balanced, features native Suricata EVE, 33 după one-hot):**
| Evaluare | ATTACK F1 | ATTACK precision | ATTACK recall | accuracy |
|---|---|---|---|---|
| 5-fold StratifiedKFold CV | **0.986** | 0.976 | 0.996 | 0.9993 |
| Holdout 30% | 0.986 | 0.978 | 0.993 | 0.9993 |

Confusion (CV): TN 18038 / FP 11 / **FN 2** / TP 456 (din 458 atacuri, prinde 456). Top features:
`dest_port`, `app_proto_failed`, `pkts_toserver`, `bytes_toclient`, `total_bytes`, `bytes_ratio`.
**Caveat onest:** benign-ul e dominat de trafic infra (VXLAN/calico/DNS) ușor separabil de atac → scorul mare
reflectă parțial asta; cazurile grele sunt cele 11 FP + 2 FN. `dest_port` ca top feature = ușor risc de leakage
(scan = porturi multe, DVWA = 80), dar e un semnal legitim.

**Concluzia care leagă totul (Cap E):**
- Model pe **date proprii** (node-2, features native) → **F1 0.986 pe propriul mediu**, fără domain shift. ✅
- Model pe **CIC** aplicat cross-environment → **F1 ~0.0001** (secțiunea 2). 💥
- → confirmă empiric: pentru deployment real, modelul TREBUIE antrenat pe date din mediul propriu;
  dataset-urile publice servesc doar la validarea metodei + cuantificarea domain shift-ului.

## 5. Limitări documentate
1. **Domain shift** — modelele nu transferă între dataset-uri (cuantificat mai sus).
2. **Dezechilibru de clase** — clasele rare slab detectate în multiclass.
3. **Feature mismatch** — features CICFlowMeter ≠ câmpurile Suricata EVE; integrarea live cere extractor comun.
4. **ML ≠ explicabil** ca regulile — verdictele RF sunt mai greu de justificat decât o regulă Falco/Suricata.
