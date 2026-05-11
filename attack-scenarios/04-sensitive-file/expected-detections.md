# Scenariul 4 — Sensitive File / Secret Access

**MITRE ATT&CK:** T1552 (Unsecured Credentials)

## Pași de atac

1. `cat /etc/shadow` — citire fișier hash parole
2. `cat /etc/gshadow` — citire fișier hash group passwords
3. `ls /var/run/secrets/kubernetes.io/serviceaccount/` — enumerare credențiale K8s montate în pod
4. `cat /var/run/secrets/kubernetes.io/serviceaccount/token` — citire ServiceAccount token (ar permite call-uri la K8s API ca pod-ul)
5. `cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt` — citire CA cert al cluster-ului

## Rezultate finale (după 3 iterații de tuning)

| Regulă | Priority | Count |
|---|---|---|
| `K8S_THREAT: Sensitive File Read in Container` | Warning | 3 |
| `K8S_THREAT: Kubernetes Secret Access from Pod` | Notice | 1 |
| `Read sensitive file untrusted` (default Falco) | Warning | 1 |
| **Total** | | **5** |

**Detection rate**: 100% (5 detecții / 5 pași de atac)
**False positive rate**: 0%

## Procesul de tuning (relevant pentru Cap D)

| Iterație | Modificare | Total | True+ | False+ |
|---|---|---|---|---|
| 0 (baseline) | macro defect blochează regulile custom | 1 | 1 | 0 |
| 1 | fix macro `custom_container` și `not_system_namespace` | 19 | 19 | 0 |
| 2 | exclude token din regula generală (rezolvă rule overlap) | 12 | 7 | 5 |
| 3 | extinde `not proc.name` cu procese infra K8s | 5 | 5 | 0 |

## Re-validare pe helm rev 22 (2026-05-11)

Re-rulat după migrarea la `collectors.containerEngine` + macro-ul `not_system_namespace` upgradeat — **rezultate identice** (5 detecții, 0 FP), dar acum output-ul Falco conține metadata k8s completă: `container_name=attacker image=docker.io/library/ubuntu k8s_ns=attack-target k8s_pod=attack-pod`. Vezi `07-data-exfiltration/expected-detections.md` (iterația C) pentru cum a fost rezolvat enrichment-ul.

## Discoveries (relevant pentru Cap 6 — Limitări)

1. **~~Plugin container@0.6.3 pe MicroK8s nu populează metadata containerd~~ — REZOLVAT (helm rev 21).** Cauza: chart-ul Helm 8.0.2 montează doar socket-urile containerd default (`/run/containerd`, `/run/k3s/...`), nu și socket-ul snap-ului MicroK8s `/var/snap/microk8s/common/run/containerd.sock`. După adăugarea lui la `collectors.containerEngine.engines.containerd.sockets` + `.engines.cri.sockets`, toate câmpurile (`container.name`, `container.image.repository/tag`, `k8s.ns.name`, `k8s.pod.name`) se populează. Macro-urile pot folosi acum `k8s.ns.name` (`not_system_namespace` a fost upgradeat). _Notă: investigația și concluzia inițială ("limitare de infrastructură") s-au dovedit greșite — era doar un socket nemontat; documentăm ambele variante pentru Cap D._

2. **Rule precedence în Falco**: când două reguli match același eveniment, **doar prima în ordine trage**. Regulile generale acoperă cele specifice → necesită exclusions explicite.

3. **Tuning iterativ pe baza testării**: liste statice de excluderi sunt insuficiente — descoperiri noi (ex: metrics-server, metrics-sidecar care citesc legitim propriul token) necesită extinderea regulilor.

## Suricata
N/A — atac local, fără trafic de rețea.

## Cross-tool correlation
Scăzut — acest scenariu e dominat de Falco. Util ca baseline simplu pentru a confirma pipeline-ul.

## False negatives confirmate
- `ls` în sine nu este detectat când nu deschide fișiere de citit (doar enumerare directă)
- mmap / memory-mapped I/O nu sunt detectate (regulile filtrează doar `evt.type in (open, openat, openat2)`)
