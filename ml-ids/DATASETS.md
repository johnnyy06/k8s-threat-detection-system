# Dataset-uri IDS pentru componenta ML (Random Forest) — documentare

Trei dataset-uri: **două publice de la CIC** (Canadian Institute for Cybersecurity, UNB) folosite pentru
validarea metodei + cuantificarea domain shift-ului, și **un dataset propriu** colectat din clusterul
tezei (secțiunea 3) pentru un model fără domain shift. Cele două CIC folosesc **CICFlowMeter** →
**schemă de features compatibilă** între ele (avantaj metodologic, vezi mai jos); dataset-ul de cluster
folosește **features native Suricata EVE** (familie diferită — vezi nota din secțiunea 3).

## 1. CIC-IDS2017
- **Sursă:** https://www.unb.ca/cic/datasets/ids-2017.html
- **Ce e:** trafic de rețea real (benign + atac), 5 zile (Lu–Vi, 3–7 iul 2017, 9–17). Luni = doar benign.
  Background traffic realist generat cu B-Profile pe 25 utilizatori (HTTP/HTTPS/FTP/SSH/email).
- **Topologie:** infrastructură completă (firewall/routere/switch-uri), atacatori în rețea externă,
  victime în LAN intern (12 mașini, Windows/Ubuntu/macOS).
- **Atacuri (8 categorii):** Brute Force (FTP/SSH), DoS/DDoS (Slowloris, Slowhttptest, Hulk, GoldenEye,
  LOIT), Heartbleed, Web (Brute Force/XSS/SQLi), Infiltration (Dropbox, Metasploit, port scan), Botnet (ARES).
- **Features:** CICFlowMeter, **>80 features** flow-based.
- **Formate:** PCAP (~51 GB total — NU); `GeneratedLabelledFlows.zip`; **`MachineLearningCSV.zip` ← FOLOSIM**
  (8 fișiere CSV pe zile/sesiuni, câteva sute MB).
- **Label:** coloana `Label` cu numele atacului (multiclass) → mapăm la binary (BENIGN vs ATTACK) sau multiclass.
- **Citare obligatorie:** Sharafaldin, Lashkari, Ghorbani — *"Toward Generating a New Intrusion Detection
  Dataset and Intrusion Traffic Characterization"*, ICISSP 2018.

### ⚠️ Probleme cunoscute CIC-IDS2017 (relevante la preprocesare — material bun pt Cap D/metodologie)
- **NaN / Infinity** în `Flow Bytes/s` și `Flow Packets/s` (împărțire la 0) → trebuie curățate/imputate.
- **Whitespace în numele coloanelor** (ex. ` Label`) → `.str.strip()`.
- **Dezechilibru sever de clase**: BENIGN domină (~80%); unele atacuri minuscule (Heartbleed ~11 rânduri,
  Infiltration ~36) → necesită strategie (class_weight, undersampling BENIGN, SMOTE, sau binary).
- **Duplicate / înregistrări redundante.**
- `Destination Port` ca feature poate cauza leakage/overfitting → de evaluat dacă-l păstrăm.
- Există o **versiune „improved/cleaned"** (Engelen et al., 2021, *"Troubleshooting an IDS Dataset"*) — de menționat.

## 2. CIC-UNSW-NB15
- **Sursă:** https://www.unb.ca/cic/datasets/cic-unsw-nb15.html
- **Ce e:** **re-extragere CIC a UNSW-NB15 original** (IXIA PerfectStorm, ~100GB pcap pe 2 zile) folosind
  **CICFlowMeter** pe aceleași pcap-uri brute → features flow refined. **NU e UNSW-NB15 originalul**
  (ăla avea 47 features Argus/Bro). Asta e cheia: features **CICFlowMeter, aceeași familie ca CIC-IDS2017**.
- **Atacuri (9 categorii):** Fuzzers, Analysis, Backdoor, Exploit, Generic, Reconnaissance, Shellcode, Worms, DoS.
- **Dimensiune:** **448.695 flow-uri** — Benign 358.332 / Malicious 90.363 (~**80/20**, deja rezonabil balansat).
- **Fișiere:** `CICFlowMeter_out.csv` (flow-uri etichetate complet), `Data.csv` (ratio 80/20), `Label.csv`
  (label-uri numerice), `Readme.txt` (mapping label-uri). **CSV only**, fără pcap.
- **Citare:** Mohammadian et al., PST 2024.

## 3. Dataset propriu — flow-uri Suricata din cluster (`cluster_flows.csv`)

- **Sursă:** clusterul tezei (MicroK8s 4 noduri), extras din Elasticsearch cu `collect_cluster_data.py`.
  **NU e un dataset public** — sunt datele tale, deci pot fi incluse în repo (mic, ~2.2 MB).
- **Ce e:** flow records `event_type: flow` de la senzorii Suricata (node-2 + node-3), etichetate
  BENIGN / ATTACK pe bază de **ground-truth** (IP-ul atacatorului + fereastra temporală a scenariilor).
- **Dimensiune:** **18.507 flow-uri** — **18.049 BENIGN / 458 ATTACK** (~2.4%, dezechilibru realist de producție).
- **Features:** **23 native Suricata EVE** (flow-based) + 4 coloane de metadata (`flow_id`, `node`, `label`,
  `scenario`). Features: `proto`, `app_proto`, `duration_ms`, `flow_age`, `bytes_toserver/toclient/total`,
  `pkts_toserver/toclient/total`, `bytes_per_s`, `pkts_per_s`, `bytes_ratio`, `pkts_ratio`, `src_port`,
  `dest_port`, `flow_state`, flag-uri TCP (`tcp_syn/ack/psh/fin/rst/urg`). One-hot pe `proto`/`app_proto`/
  `flow_state` → ~33 features la antrenare.
- **Defalcare ATTACK pe scenariu:** `s05_07_11` = **314** (scanning + exfil + lateral movement din attack-pod
  pe node-2), `s09_zap` = **144** (ZAP DAST → DVWA, inter-nod). **kube-hunter (s10) = 0** flow-uri (recon
  spre API node-1 peste TLS + raw sockets → fără `flow` events capturabile). Pe noduri: node-2 = 233, node-3 = 225.
- **Metodologie de colectare (curată — material Cap E):** benign-ul colectat dintr-o **fereastră liniștită
  de 12h peste noapte, ÎNAINTE** de rularea atacurilor → separare temporală, fără contaminare de etichetă.
  (Capcană evitată: colectarea benign pe o fereastră care include atacuri ar eticheta greșit scan-urile ca
  benign.) Atacurile rulate separat, în ferestre controlate, etichetate pe IP-ul atacatorului.
- **Finding-cheie de topologie:** pentru ca Suricata să prindă un atac, **fie atacatorul, fie ținta trebuie
  pe un nod cu senzor** (node-2/node-3, NU node-1/node-4). attack-pod pe node-2 → 314 flow-uri (vs doar 49
  când era pe node-4 fără senzor) — plasarea contează enorm.
- **Cod:** `collect_cluster_data.py` (extracție ES + labeling) → `cluster_flows.csv` → `train_cluster_rf.py`.
- **Rezultate:** vezi `RESULTS.md` §4 (RF F1 0.986 pe propriul mediu, fără domain shift).

> **De ce un al treilea dataset:** cele două CIC servesc la a *demonstra metoda* și a *cuantifica domain
> shift-ul* (RESULTS §2). Dataset-ul de cluster servesc la a arăta că, antrenat pe **date din mediul
> propriu** cu features **native pipeline-ului live** (Suricata EVE, nu CICFlowMeter), modelul funcționează
> (F1 0.986) **fără** prăbușirea de domain shift — exact argumentul de integrare reală din Cap E.

## 💡 Observație metodologică cheie (avantaj)
**Ambele folosesc CICFlowMeter → schemă de features ~identică.** Asta permite:
1. **Preprocesare/feature schema unificată** (un singur pipeline pentru ambele).
2. **Studiu de domain shift CUANTIFICAT** (experiment puternic pentru Cap E): antrenezi RF pe CIC-IDS2017,
   testezi pe CIC-UNSW-NB15 (și invers) → măsori cât scade F1 la cross-dataset. Demonstrezi EMPIRIC
   limitarea „domain shift" despre care discutam — exact ce te-ar întreba un examinator.
3. Și e aceeași familie de features cu ce ai putea extrage din traficul tău cu CICFlowMeter (relevant
   pentru o eventuală integrare live Suricata).

## Plan de lucru offline (reconfirmat)
1. Per-dataset (CIC): încărcare CSV → cleanup (NaN/Inf, whitespace, duplicate) → encoding label → train/test split.
2. **Random Forest** per dataset: metrici (accuracy/precision/recall/F1, confusion matrix, ROC-AUC, feature importance).
3. **Cross-dataset** (train pe unul, test pe celălalt) → cuantifică domain shift.
4. **Model pe date proprii din cluster** (secțiunea 3): RF pe `cluster_flows.csv`, features native Suricata EVE → F1 0.986 fără domain shift.
5. Documentare rezultate pentru teză (Cap E: ML ca direcție; comparație rule-based ↔ ML; date publice vs date proprii).

## Acces / etică
- **CIC-IDS2017 + CIC-UNSW-NB15:** publice, descărcabile gratuit (CIC cere doar citarea). De inclus citările în Bibliografie (Cap F). **NU se commit-uie în repo** (mari + redistribuire) — vezi sursele de mai sus.
- **`cluster_flows.csv`:** date proprii, generate din clusterul tezei — fără constrângeri de citare/redistribuire; pot fi incluse în repo (conțin doar metadate de flow, nu payload-uri).
