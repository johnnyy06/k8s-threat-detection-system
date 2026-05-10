# Scenariul 5 — Network Scanning (T1046)

**MITRE ATT&CK:** T1046 (Network Service Discovery)

**Primul scenariu cu cross-tool real Falco + Suricata.**

## Pași de atac

1. `apt-get install -y nmap` — descărcare + instalare nmap
2. `nmap -sT -p 1-1000 10.152.183.1` — TCP connect scan, primele 1000 porturi pe Kubernetes API svc
3. `nmap -sS -p 22,80,443,8080,3306 10.1.139.66` — SYN scan pe DVWA pod
4. `nmap -sV -p 80 10.1.139.66` — service version detection pe DVWA
5. `nc -zv 10.1.247.31 80 8080 8443` — netcat connect scan pe Falco daemon pod

## Rezultate finale (după fix `rule_matching: all`)

### Falco

| Regulă | Priority | Count | Tip |
|---|---|---|---|
| `K8S_THREAT: Network Scanning Tool in Container` | Warning | 6 | Custom — TARGET |
| `K8S_THREAT: Data Exfiltration - Transfer Tool in Container` | Warning | 3 | Custom (BONUS — `nc` în lista exfil) |
| `K8S_THREAT: Crypto Mining Pool Connection` | Warning | 1 | Custom (port match accidental) |
| `K8S_THREAT: Package Manager in Running Container` | Warning | 1 | Custom |
| `Contact K8S API Server From Container` | Notice | 1995 | Default — port scan al API service |
| `Drop and execute new binary in container` | Critical | 6 | Default — nmap/nc nou instalate |
| `Packet socket created in container` | Notice | 5 | Default — `nmap -sS` raw socket |

**Total Falco events:** 2017
**Custom rules fire count:** 11 (4 reguli K8S_THREAT diferite)

### Suricata

| Signature | Count |
|---|---|
| SURICATA STREAM 3way handshake wrong seq wrong ack | 297 |
| SURICATA STREAM Packet with invalid timestamp | 172 |
| SURICATA STREAM CLOSEWAIT FIN out of window | 23 |
| SURICATA HTTP Host part of URI is invalid | 11 |
| SURICATA HTTP unable to match response to request | 11 |
| SURICATA STREAM FIN out of window | 3 |

**Total Suricata alerts:** 517
**Total Suricata events (incl. flow/stats):** ~15,500

### Cross-tool correlation
- Fiecare scan pas a fost detectat în **AMBELE layere** (Falco syscall + Suricata network)
- Same time window, distinct evidence types
- Suricata STREAM alerts indică TCP transport anomalies (scan pattern)
- Falco custom rule confirmă cauza la process layer

## Cauza descoperită (Cap 6 — Lessons Learned)

Inițial regula `K8S_THREAT: Network Scanning Tool` NU tragea, deși:
- Schema validation: OK
- Rule loaded și compiled în engine (`enabled: true`)
- Toate condițiile match-uiesc evenimentul execve

Investigație în 2 sesiuni a relevat 2 bug-uri:

### Bug 1: Schema validation duplicate (rezolvat)
Edit-uri repetate pe configmap au introdus duplicate `source: syscall` în rule definition. Schema parser-ul Falco a marcat regula ca invalid (item #21 array "Object contains property '' "). **Schema warning** dar Falco încă încărca restul fișierului.

### Bug 2: `rule_matching: first` (cauza fundamentală)
Falco are setarea `rule_matching` cu default `first`:
- `first` (default) — fires DOAR PRIMA regulă match per event
- `all` — fires TOATE regulile match per event

Cu `first`, când nmap se execută:
1. Falco evaluează rule-urile în ordine
2. `Drop and execute new binary in container` (default, încărcată din `falco_rules.yaml` ÎNAINTE custom-rules) → match → fires
3. `K8S_THREAT: Network Scanning Tool` → niciodată evaluată (Falco oprește)

**Fix:** adăugat `rule_matching: all` în falco helm values.

### De ce alte reguli custom funcționau
Regulile custom care AVEAU condiții unice (Sudo or Su, Package Manager, Sensitive File Read) tragerau pentru că nu se suprapuneau cu default rules pe aceeași combinație de fields. Doar cele care suprapuneau `evt.type=execve and proc.name in (...)` cu Drop and execute new binary erau silent suprimate.

## Tools folosite în investigație
- `falco --validate <file>` — validează rule-uri standalone (output JSON)
- `falco -L` — listează toate rule-urile loaded cu compiled conditions (output JSON detaliat per rule)
- `falco -V <file1> -V <file2>` — validate multiple files together
- `kubectl exec -n falco POD -c falco -- falco --help` — toate opțiunile

## False negatives confirmate
- Scan **slow** (`-T0`, `-T1`) — Suricata sub threshold
- Scanări via K8s ClusterIP svc (kube-proxy NAT) — depinde de plasarea Suricata sensors
- Scan UDP — testat doar TCP scenarios

## Cifre pentru tabel "Detection Rate per Scenario" (Cap D)

| Metric | Valoare |
|---|---|
| Pași de atac | 5 |
| Pași detectați (oricare layer) | 5 (100%) |
| Reguli active | 7 (4 custom K8S_THREAT + 3 default) |
| Detecții Falco totale | 2017 |
| Detecții Suricata totale (alerts) | 517 |
| **Cross-tool detection rate** | **100%** |
| **False positive rate** | scăzut (Crypto Mining Pool 1 event accidental) |
