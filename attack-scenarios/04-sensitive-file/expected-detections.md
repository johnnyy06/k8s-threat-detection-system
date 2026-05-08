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

## Discoveries (relevant pentru Cap 6 — Limitări)

1. **Plugin container@0.6.3 pe MicroK8s nu populează metadata containerd** — `container.name`, `container.image.repository`, `k8s.ns.name`, `k8s.pod.name` toate `null`. Macro-urile cu condition pe aceste câmpuri **nu pot fi folosite** pe acest cluster.

2. **Rule precedence în Falco**: când două reguli match același eveniment, **doar prima în ordine trage**. Regulile generale acoperă cele specifice → necesită exclusions explicite.

3. **Tuning iterativ pe baza testării**: liste statice de excluderi sunt insuficiente — descoperiri noi (ex: metrics-server, metrics-sidecar care citesc legitim propriul token) necesită extinderea regulilor.

## Suricata
N/A — atac local, fără trafic de rețea.

## Cross-tool correlation
Scăzut — acest scenariu e dominat de Falco. Util ca baseline simplu pentru a confirma pipeline-ul.

## False negatives confirmate
- `ls` în sine nu este detectat când nu deschide fișiere de citit (doar enumerare directă)
- mmap / memory-mapped I/O nu sunt detectate (regulile filtrează doar `evt.type in (open, openat, openat2)`)
