# k8s-threat-detection-system

Integrated cyber threat detection, correlation, and automated response system for Kubernetes environments, combining Falco (runtime security), Suricata (network IDS/IPS), and the ELK Stack (centralized logging & analytics).

Built as a bachelor's thesis project at the Faculty of Information Systems and Cyber Security.

## Overview

This project implements a **defense-in-depth** security monitoring pipeline for Kubernetes clusters. Instead of relying on a single detection tool, it correlates alerts from multiple layers — container runtime (Falco), network traffic (Suricata), and centralized logs (ELK) — to provide a unified view of security incidents and enable automated response actions.

**Key principle:** Deterministic, rule-based detection (no ML/AI) — focused on reliability and explainability.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    MicroK8s Cluster                      │
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│  │   VM1    │  │   VM2    │  │   VM3    │  │   VM4   │ │
│  │ Control  │  │ Security │  │   App    │  │ Monitor │ │
│  │  Plane   │  │  Node    │  │  Node    │  │  Node   │ │
│  │ + Falco  │  │+Suricata │  │+Workloads│  │ + ELK   │ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬────┘ │
│       │              │              │              │     │
│       └──────────────┴──────────────┴──────────────┘     │
│                           │                              │
│                     Filebeat/Logstash                     │
│                           │                              │
│                    Elasticsearch                         │
│                           │                              │
│                   Kibana Dashboards                      │
│              (cross-tool correlation)                    │
└─────────────────────────────────────────────────────────┘
```

**Detection & response pipeline:**

```
Falco alert ──→ Filebeat ──→ Logstash ──→ Elasticsearch ──→ Kibana
                                ↑                            (correlation
Suricata alert ─→ Filebeat ────┘                             & dashboards)

Falco alert ──→ Falco Talon ──→ Kill container / Isolate pod
```

## Tech Stack

| Component | Tool | Role |
|-----------|------|------|
| Orchestration | MicroK8s | Lightweight Kubernetes distribution |
| Runtime Security | Falco + Falco Talon | Syscall monitoring, automated response |
| Network IDS/IPS | Suricata | Network traffic analysis, signature-based detection |
| Log Pipeline | Filebeat → Logstash | Log collection and processing |
| Storage & Search | Elasticsearch | Centralized log storage and querying |
| Visualization | Kibana | Dashboards, investigation, cross-tool correlation |
| Infrastructure | 4× Ubuntu 22.04 VMs | University datacenter |

## Project Structure

```
k8s-threat-detection-system/
├── README.md
├── .gitignore
├── infrastructure/          # MicroK8s setup, VM configurations
├── falco/
│   ├── rules/               # Custom Falco rules
│   └── config/              # falco.yaml, Helm values
├── falco-talon/
│   └── config/              # Automated response rules
├── suricata/
│   ├── rules/               # Custom Suricata rules
│   └── config/              # suricata.yaml
├── elk/
│   ├── logstash/            # Pipeline configs, filters
│   ├── elasticsearch/       # Index templates, ILM policies
│   └── filebeat/            # Filebeat configs per node
├── dashboards/              # Kibana exported dashboards (.ndjson)
├── attack-scenarios/        # Attack scripts + documentation per scenario
│   ├── 01-container-escape/
│   ├── 02-crypto-mining/
│   └── ...
└── docs/                    # Architecture diagrams, notes
```

## Attack Scenarios

Planned end-to-end attack scenarios with multi-layer detection:

| # | Scenario | Falco | Suricata | Response |
|---|----------|-------|----------|----------|
| 1 | Container escape attempt | ✓ | | Kill container |
| 2 | Crypto mining detection | ✓ | ✓ | Isolate pod |
| 3 | Reverse shell | ✓ | ✓ | Kill container |
| 4 | Sensitive file access | ✓ | | Alert |
| 5 | Network scanning | | ✓ | Isolate pod |
| 6 | Privilege escalation | ✓ | | Kill container |
| 7 | Data exfiltration | ✓ | ✓ | Isolate pod |
| 8 | Malicious image deployment | ✓ | | Alert |

Each scenario is documented with: attack description, execution steps, expected detections per tool, correlated view in Kibana, and automated response action.

## Status

- [x] MicroK8s cluster (4 VMs)
- [x] ELK pipeline (Falco → Filebeat → Logstash → Elasticsearch → Kibana)
- [x] Falco installed (default rules)
- [x] Suricata installed and configured
- [ ] Custom Falco rules
- [ ] Custom Suricata rules
- [ ] Kibana dashboards
- [ ] Cross-tool correlation in ELK
- [ ] Falco Talon (automated response)
- [ ] Full attack scenarios (5-8 documented)

## License

To be added.
