# k8s-threat-detection-system

Integrated cyber threat detection, correlation, and automated response system for Kubernetes environments, combining Falco (runtime security), Suricata (network IDS/IPS), and the ELK Stack (centralized logging & analytics).

Built as a bachelor's thesis project at the Faculty of Information Systems and Cyber Security.

## Overview

This project implements a **defense-in-depth** security monitoring pipeline for Kubernetes clusters. Instead of relying on a single detection tool, it correlates alerts from multiple layers — container runtime (Falco), network traffic (Suricata), and centralized logs (ELK) — to provide a unified view of security incidents and enable automated response actions.

**Key principle:** Deterministic, rule-based detection (no ML/AI) — focused on reliability and explainability.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                       MicroK8s Cluster (4 VMs)                    │
│                                                                   │
│   node-1            node-2            node-3            node-4     │
│  control plane     security node     app node          monitoring │
│  + dqlite          + Suricata        + workloads /     + ELK       │
│                    (systemd)         vulnerable apps   (systemd)   │
│                                                                   │
│   ── Falco runs as a DaemonSet on ALL nodes (modern eBPF) ──       │
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

Falco emits alerts via falcosidekick to a Logstash HTTP input; Suricata writes EVE JSON that Logstash also ingests. Logstash (`elk/logstash/logstash-security.conf`) merges both streams into a single Elasticsearch index `security-YYYY.MM.dd` with `tags: [falco]` or `tags: [suricata]`, so alerts from both layers can be correlated on common fields (`@timestamp`, `k8s.pod.name` / `container.id`, `dest_ip`). Suricata runs as a systemd service (monitoring the cluster network interface), not as a pod.

## Tech Stack

| Component | Tool | Role |
|-----------|------|------|
| Orchestration | MicroK8s (v1.32) | Lightweight Kubernetes distribution |
| Runtime Security | Falco (Helm chart 8.0.2 / app 0.43.x, modern eBPF) + Falco Talon | Syscall monitoring; automated response |
| Network IDS/IPS | Suricata (systemd) | Network traffic analysis, signature-based detection |
| Log Pipeline | falcosidekick / Suricata EVE → Logstash | Alert collection and normalization |
| Storage & Search | Elasticsearch | Unified `security-*` index, querying |
| Visualization | Kibana | Dashboards, investigation, cross-tool correlation |
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
│   └── config/              # Talon ConfigMap + Deployment (automated-response rules)
├── suricata/
│   ├── config/
│   └── rules/suricata-local.rules   # local custom rules (main detection still via the ET ruleset)
├── elk/
│   ├── logstash/logstash-security.conf   # pipeline: Falco + Suricata → unified security-* index
│   ├── elasticsearch/       # (index templates / ILM — TBD)
│   └── filebeat/            # (TBD)
├── dashboards/              # Kibana exported dashboards (.ndjson) — TBD
├── attack-scenarios/
│   ├── attack-target-setup.yaml      # the persistent `attack-pod` (namespace attack-target)
│   ├── 01-container-escape/  (attack.sh, expected-detections.md, escape-pod.yaml)
│   ├── 02-crypto-mining/     (attack.sh, expected-detections.md)
│   ├── ... 03–08 ...
│   ├── 09-owasp-zap/         (planned)
│   └── 10-kube-hunter/       (planned)
└── docs/                    # baseline stats, notes
```

Each `attack-scenarios/NN-name/` folder contains `attack.sh` (executes the attack against the test pod, then queries Elasticsearch to report what each tool detected) and `expected-detections.md` (rules expected to fire, actual results, tuning iterations performed, and lessons learned — input for thesis chapter D "Crearea soluției tehnice" and chapter 6 "Limitări").

## Attack Scenarios

| # | Scenario | MITRE | Falco | Suricata | Status |
|---|----------|-------|-------|----------|--------|
| 01 | Container escape (privileged pod: sysrq-trigger, runtime socket, nsenter, chroot, unshare) | T1611 | ✓ (13 detections) | — | ✅ done & validated |
| 02 | Crypto mining (renamed miner binaries + pool-port connects; no real miner) | T1496 | ✓ (17 detections) | — | ✅ done & validated |
| 03 | Reverse shell (`/dev/tcp`, mkfifo FIFO, `nc -e`, exec-FD, nc listeners) | T1059 | ✓ (~30 detections) | — (loopback) | ✅ done & validated |
| 04 | Sensitive file / secret access (`/etc/shadow`, SA token, CA cert) | T1552 | ✓ (5 detections) | — | ✅ done & validated |
| 05 | Network scanning (nmap TCP-connect / SYN / version scans, nc) | T1046 | ✓ | ✓ (cross-tool) | ✅ done & validated |
| 06 | Privilege escalation (setuid bits, `su`/`sudo`, package install) | T1548 | ✓ (8 detections) | — | ✅ done & validated |
| 07 | Data exfiltration (curl/wget HTTP POST, raw-TCP nc, DNS tunneling) | T1048 / T1071.004 | ✓ (43 detections) | telemetry only | ✅ done & validated |
| 08 | Malicious deployment (privileged pod deploy + apt / curl-download / chmod+x in /tmp / exec) | T1610 | ✓ (9 detections) | — | ✅ done & validated |
| 09 | OWASP ZAP DAST scan against the vulnerable web app | T1595 | partial | ✓ (cross-tool) | ⏳ planned |
| 10 | kube-hunter Kubernetes pentest | T1046 / T1526 | ✓ | ✓ | ⏳ planned |

Notes: scenario 1 (deploying the privileged pod) and scenario 8 (deploying the malicious workload) are *not* detected by Falco at deployment time — Falco sees the **consequences** of running a malicious container, not the act of creating it; deployment-time detection would need admission control (OPA/Kyverno) or the `k8saudit` plugin. Scenarios 3 and 7 generate little/no Suricata-detectable traffic (loopback / standard protocols to reputable destinations) — documented as a limitation; Suricata still captures the telemetry.

## Status

**Done**
- [x] 4-VM MicroK8s cluster (node-1 control plane / node-2 Suricata / node-3 workloads / node-4 ELK)
- [x] ELK pipeline end-to-end (Falco via falcosidekick + Suricata EVE → Logstash → Elasticsearch → Kibana, unified `security-*` index)
- [x] Falco deployed (Helm, modern eBPF) with the full set of custom `K8S_THREAT:` rules (currently helm revision 25)
- [x] Falco container/k8s metadata enrichment fixed (`collectors.containerEngine` + MicroK8s containerd socket)
- [x] Suricata deployed (systemd) with a local custom rules file
- [x] 8 of 10 attack scenarios fully implemented and validated end-to-end (`attack-scenarios/01..08/`)

**In progress / pending**
- [ ] Attack scenarios 09 (OWASP ZAP) and 10 (kube-hunter)
- [ ] Kibana dashboards (`dashboards/` — exported `.ndjson`)
- [ ] Dedicated cross-tool correlation views / saved queries in Kibana (the data is already unified in `security-*`; correlation is currently done ad-hoc)
- [ ] Falco Talon — config files exist (`falco-talon/config/`), end-to-end deployment and validation pending
- [ ] Deeper Suricata rule tuning
- [ ] Thesis chapters B (theory), C (state of the art), D (implementation) — written outside this repo

**Future directions (not in scope of the thesis; mentioned in the conclusions chapter):** AI/ML-assisted detection (anomaly detection, false-positive reduction), Zero Trust.

## Working with this repo

`kubectl`/`helm` are run from the laptop with a pre-configured kubeconfig. The cluster's internal `10.11.0.x` IPs are not routable from the laptop — reach Elasticsearch/Kibana via the node-4 floating IP `10.102.14.31` (`:9200` ES, `:5601` Kibana). After editing `falco/config/custom-values.yaml`, `helm upgrade falco falcosecurity/falco -n falco --version 8.0.2 -f custom-values.yaml` and wait for the DaemonSet rollout (slow — ~5-15 min; the eBPF driver is rebuilt per pod on this disk). Custom Falco rules live in the `customRules:` block of `custom-values.yaml`, **not** in `falco/rules/custom-rules.yaml` (that copy is stale). See `CLAUDE.md` for the full command set and gotchas.

## License

(unspecified)
