# k8s-threat-detection-system

Integrated cyber threat detection, correlation, and automated response system for Kubernetes environments, combining Falco (runtime security), Suricata (network IDS/IPS), and the ELK Stack (centralized logging & analytics).

Built as a bachelor's thesis project.

## Overview

This project implements a **defense-in-depth** security monitoring pipeline for Kubernetes clusters. Instead of relying on a single detection tool, it correlates alerts from multiple layers — container runtime (Falco), network traffic (Suricata), and centralized logs (ELK) — to provide a unified view of security incidents and enable automated response actions.

**Key principle:** Deterministic, rule-based detection — focused on reliability and explainability.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                       MicroK8s Cluster (4 VMs)                    │
│                                                                   │
│   node-1            node-2            node-3            node-4     │
│  control plane     worker            app/worker        monitoring │
│  + dqlite          + Suricata        + Suricata        + ELK       │
│                    sensor (systemd)  sensor (systemd)  (systemd)   │
│                                      + workloads /                 │
│                                      vulnerable apps               │
│                                                                   │
│   ── Falco runs as a DaemonSet on ALL nodes (modern eBPF) ──       │
│   ── Suricata = per-node systemd sensors on node-2 + node-3 ──     │
│                                                                   │
│   Falco ──falcosidekick webhook──┐                                │
│                                  ▼                                │
│   Suricata EVE JSON ──────────► Logstash ──► Elasticsearch        │
│                                  (normalizes both into one         │
│                                   daily index: security-YYYY.MM.dd │
│                                   tagged `falco` | `suricata`)     │
│                                          │                        │
│                                       Kibana                       │
│                              (cross-tool correlation,              │
│                               dashboards, investigation)           │
│                                                                   │
│   Falco alert ──► Falco Talon ──► kill container / isolate pod     │
│                   (NetworkPolicy)                                  │
└──────────────────────────────────────────────────────────────────┘
```

Falco emits alerts via falcosidekick to a Logstash HTTP input; Suricata writes EVE JSON that Logstash also ingests. Logstash (`elk/logstash/logstash-security.conf`) merges both streams into a single Elasticsearch index `security-YYYY.MM.dd` with `tags: [falco]` or `tags: [suricata]`, so alerts from both layers can be correlated on common fields (`@timestamp`, `k8s.pod.name` / `container.id`, `dest_ip`). Suricata runs as **per-node systemd sensors on node-2 + node-3** (not as a pod); each sensor sniffs only its own node's `ens3` (AF_PACKET, VXLAN-decoded), so coverage is per-node / sensor-near-target — a single node does **not** cover the whole cluster. A separate metrics stack (Prometheus + Grafana, namespace `observability`) monitors cluster health, kept distinct from the security log pipeline.

## Tech Stack

| Component | Tool | Role |
|-----------|------|------|
| Orchestration | MicroK8s (v1.32) | Lightweight Kubernetes distribution |
| Runtime Security | Falco (Helm chart 8.0.2 / app 0.43.x, modern eBPF) + Falco Talon | Syscall monitoring; automated response |
| Network IDS/IPS | Suricata (systemd, per-node sensors on node-2 + node-3) | Network traffic analysis; ET Open + custom K8s signatures |
| Log Pipeline | falcosidekick / Suricata EVE → Logstash | Alert collection and ECS normalization |
| Storage & Search | Elasticsearch | Unified `security-*` + `falco-talon-*` indices, querying |
| Visualization | Kibana | Dashboards (Overview + MITRE), investigation, cross-tool correlation |
| Metrics | Prometheus + Grafana (Helm, namespace `observability`) | Cluster health metrics (separate from the security log pipeline) |
| Infrastructure | 4× Ubuntu 22.04 VMs | University datacenter |

## Repository Layout

```
k8s-threat-detection-system/
├── CLAUDE.md                # Guidance for Claude Code / contributors
├── README.md
├── infrastructure/
│   ├── ansible/             # Playbooks for VM / cluster setup
│   └── vulnerable-apps.yaml # DVWA & other test targets
├── falco/
│   ├── config/
│   │   └── custom-values.yaml   # Helm values — INCLUDES the custom rules inline (customRules block); this is what's deployed
│   └── rules/
│       └── custom-rules.yaml    # standalone copy — STALE, not used by the deploy (reference only)
├── falco-talon/
│   ├── values/talon-values.yaml   # Helm values — response rules (config.rulesOverride); deployed via chart 0.4.0
│   ├── config/config.yaml         # native config, applied as an override of the falco-talon-config secret
│   └── README.md                  # runbook + chart-bug workarounds
├── suricata/
│   ├── systemd-sensors/     # per-node sensor setup (node-2 + node-3) + README
│   └── rules/suricata-local.rules   # 3 custom K8s rules (sid 1000010-12); main detection via ET Open ruleset
├── elk/
│   └── logstash/logstash-security.conf   # pipeline: Falco + Suricata → unified security-* index (ECS-normalized)
├── observability/           # Prometheus + Grafana (2 standalone Helm charts, namespace observability) — cluster metrics
├── ml-ids/                  # exploratory: Random Forest IDS on CIC-IDS2017 / CIC-UNSW-NB15 (Cap E)
├── dashboards/              # Kibana dashboards (.ndjson): Overview + MITRE (built via Python)
├── attack-scenarios/
│   ├── attack-target-setup.yaml      # the persistent `attack-pod` (namespace attack-target, pinned node-2)
│   ├── 01-container-escape/  (attack.sh, expected-detections.md, escape-pod.yaml)
│   ├── 02-crypto-mining/ ... 08-malicious-deployment/
│   ├── 09-owasp-zap/         (zap-scan-job.yaml — containerized DAST)
│   ├── 10-kube-hunter/       (kube-hunter-job.yaml — containerized pentest)
│   └── 11-lateral-movement/  (reuses attack-pod + SA token)
└── docs/
    ├── diagrams/            # architecture (draw.io) + flows (Mermaid) for the thesis
    └── baseline/            # ES baseline stats
```

Each `attack-scenarios/NN-name/` folder contains `attack.sh` (executes the attack against the test pod, then queries Elasticsearch to report what each tool detected) and `expected-detections.md` (rules expected to fire, actual results, tuning iterations performed, and lessons learned — input for thesis chapter D "Crearea soluției tehnice" and chapter 6 "Limitări").

## Attack Scenarios

| # | Scenario | MITRE | Falco | Suricata | Status |
|---|----------|-------|-------|----------|--------|
| 01 | Container escape (privileged pod: sysrq-trigger, runtime socket, nsenter, chroot, unshare) | T1611 | ✓ (13) | — | ✅ done & validated |
| 02 | Crypto mining (renamed miner binaries + pool-port connects; no real miner) | T1496 | ✓ (17) | — | ✅ done & validated |
| 03 | Reverse shell (`/dev/tcp`, mkfifo FIFO, `nc -e`, exec-FD, nc listeners) | T1059 | ✓ (~34) | — (loopback) | ✅ done & validated |
| 04 | Sensitive file / secret access (`/etc/shadow`, SA token, CA cert) | T1552 | ✓ (6) | — | ✅ done & validated |
| 05 | Network scanning (nmap TCP-connect / SYN / version scans, nc) | T1046 | ✓ | ✓ (ET SCAN sigs) | ✅ done & validated |
| 06 | Privilege escalation (setuid bits, `su`/`sudo`, package install) | T1548 | ✓ (9) | — | ✅ done & validated |
| 07 | Data exfiltration (curl/wget HTTP POST, raw-TCP nc, DNS tunneling) | T1048 / T1071.004 | ✓ (~11) | ✓ (DNS sid 1000012 + HTTP `.tar.gz`) | ✅ done & validated |
| 08 | Malicious deployment (privileged pod deploy + apt / curl-download / chmod+x in /tmp / exec) | T1610 | ✓ (10) | — | ✅ done & validated |
| 09 | OWASP ZAP DAST scan against DVWA | T1190 / T1595 | 8 (scanner pod only) | ✓ (~745 alerts, ET web sigs) | ✅ done & validated |
| 10 | kube-hunter Kubernetes pentest (`--pod --active`) | T1046 / T1613 | ✓ (14) | ✓ (cloud-metadata IMDS, sid 1000010) | ✅ done & validated |
| 11 | Lateral movement (SA-token theft → K8s API pivot → east-west) | T1550 / T1021 | ✓ (31) | ✓ (east-west: mySQL 3306, curl UA) | ✅ done & validated |

Notes:
- **Deployment-time blind spot:** scenario 1 (privileged pod) and scenario 8 (malicious workload) are *not* detected by Falco at deployment time — Falco sees the **consequences** of running a malicious container, not the act of creating it. Deployment-time prevention needs admission control (PSA / Kyverno) — analyzed in `docs/admission-control-recommendation.md` (thesis Cap 6).
- **Suricata coverage depends on sensor placement:** the attacker pod is pinned to **node-2** (which has a sensor and is *not* a target), so its outbound traffic and its inter-node traffic to DVWA (node-3, also a sensor) are captured (sensor-near-target). Scenario 3 (reverse shell) stays Falco-only — loopback traffic doesn't traverse a NIC. Scenario 7 (data exfiltration): Suricata detects DNS tunneling (custom rule `sid 1000012`) and cleartext-HTTP archive exfil (`ET WEB_SERVER ... *.tar.gz in POST body`); only **TLS-encrypted** exfil evades the NIDS (covered by Falco at the tool level).
- **Falco UDP enrichment caveat:** the custom `DNS Exfiltration Suspicion` Falco rule currently doesn't fire (a modern-eBPF `fd.*` enrichment edge case on UDP network events, [falco#3501](https://github.com/falcosecurity/falco/issues/3501)); DNS tunneling is detected at the NIDS layer instead (Suricata `sid 1000012`).

## Status

**Done**
- [x] 4-VM MicroK8s cluster (node-1 control plane / node-2 + node-3 workers with Suricata sensors / node-4 ELK)
- [x] ELK pipeline end-to-end (Falco via falcosidekick + Suricata EVE → Logstash → Elasticsearch → Kibana, unified `security-*` index, ECS-normalized)
- [x] Falco deployed (Helm, modern eBPF) with the full set of custom `K8S_THREAT:` rules (currently **helm revision 30**, incl. FIM scoped rules)
- [x] Falco container/k8s metadata enrichment fixed (`collectors.containerEngine` + MicroK8s containerd socket)
- [x] Suricata deployed — **per-node systemd sensors on node-2 + node-3** (sensor-near-target), ET Open + 3 custom K8s rules
- [x] **All 11 attack scenarios** fully implemented and validated end-to-end (`attack-scenarios/01..11/`), full re-run 2026-06
- [x] **Falco Talon automated response** deployed & validated (Helm chart 0.4.0; reverse-shell → isolate/label, crypto → terminate; ES notifier → `falco-talon-*` index)
- [x] **Prometheus + Grafana** observability stack (2 standalone Helm charts, namespace `observability`) for cluster metrics
- [x] Kibana dashboards — Overview + MITRE (`dashboards/`, built via Python)

**In progress / pending**
- [ ] Additional Kibana dashboards + dedicated cross-tool correlation saved views (data already unified in `security-*`)
- [ ] Falco/Suricata FP tuning candidates (FIM `ld.so.cache` on package installs; Falco Talon self-detection — see scenario docs)
- [ ] Exploratory ML/IDS component (`ml-ids/` — Random Forest on CIC-IDS2017 / CIC-UNSW-NB15; cross-dataset domain shift)

**Future directions (mentioned in the conclusions chapter):** admission control as a prevention layer (PSA / Kyverno — see `docs/admission-control-recommendation.md`), AI/ML-assisted detection (anomaly detection, FP reduction), Zero Trust, cluster-wide NIDS coverage (Suricata DaemonSet).

## Setup (first-time)

Cluster endpoints (Kibana, Elasticsearch) and Kibana data view IDs are read from `.env` at repo root — gitignored to keep internal IPs and identifiers out of public history.

```bash
cp .env.example .env
# Edit .env with your actual cluster endpoints and data view UUIDs
```

Required variables (see `.env.example` for the full list with comments):
- `KIBANA_URL` — used by `dashboards/*/build.py`
- `ES_URL` — used by `attack-scenarios/*/attack.sh`
- `KIBANA_DATA_VIEW_ID`, `KIBANA_DATA_VIEW_ECS_ID` — UUIDs of the two data views the dashboards reference

The loaders are at `dashboards/_config.py` (Python) and `attack-scenarios/_env.sh` (bash). Both error out with clear instructions if `.env` is missing or has placeholder values.

## Working with this repo

`kubectl`/`helm` are run from the laptop with a pre-configured kubeconfig. The cluster's internal `10.11.0.x` IPs are not routable from the laptop — reach Elasticsearch/Kibana via the node-4 floating IP (set in `.env`). After editing `falco/config/custom-values.yaml`, `helm upgrade falco falcosecurity/falco -n falco --version 8.0.2 -f custom-values.yaml -f local-values.yaml` (the gitignored `local-values.yaml` holds the deployment-specific Logstash endpoint) and wait for the DaemonSet rollout (slow — ~5-15 min; the eBPF driver is rebuilt per pod on this disk). Custom Falco rules live in the `customRules:` block of `custom-values.yaml`, **not** in `falco/rules/custom-rules.yaml` (that copy is stale). See `CLAUDE.md` for the full command set and gotchas.

## License

(unspecified)
