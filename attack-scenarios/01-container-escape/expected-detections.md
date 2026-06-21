# Scenariul 1 — Container Escape

**MITRE ATT&CK:** T1611 (Escape to Host)

## Pași de atac

1. **Deploy pod cu primitive de escape** — `kubectl apply` un pod `escape-pod` (privileged, `hostPID: true`, `hostNetwork: true`, hostPath `/` montat la `/host`, socket-ul containerd MicroK8s montat la `/run/containerd/containerd.sock`). [T1611]
2. **Acces `/proc/sysrq-trigger`** — `head -c 0 /proc/sysrq-trigger` (deschis read-only; NU scriem — scrierea `c` ar bloca host-ul). Interfață kernel globală accesibilă dintr-un container privilegiat.
3. **Acces socket-ul container runtime** — `cat /run/containerd/containerd.sock` (open() pe socket-ul montat). Cu acces la socket, un atacator poate crea containere privilegiate pe host = escape complet.
4. **`nsenter` în namespace-urile host init** — `nsenter -t 1 -m -u -i -n -p -- hostname` (PID 1 = init-ul host-ului, vizibil prin `hostPID`). Breakout direct în namespace-urile host-ului.
5. **`chroot` în host root** — `chroot /host /bin/sh -c 'id; head -1 /etc/shadow; cat /etc/hostname'` — pivot în filesystem-ul host-ului montat la `/host`, citire `/etc/shadow` al host-ului.
6. **`unshare --mount`** — `unshare --mount --fork bash -c '...'` — creare mount namespace nou (primitivă folosită în lanțuri de escape).
7. **Cleanup** — `kubectl delete pod escape-pod`.

## Reguli relevante

| Regulă | Tip | Priority | Match pe |
|---|---|---|---|
| `K8S_THREAT: Container Escape - Sensitive Mount Access` | custom | Critical | `open`/`openat` pe `/proc/sysrq-trigger`, `/proc/acpi`, `/var/run/docker.sock`, `/run/containerd/containerd.sock`, `/var/lib/kubelet/pods/.../secrets/`, `/etc/kubernetes` — pașii 2, 3 |
| `K8S_THREAT: Container Escape - Nsenter or Chroot Usage` | custom | Critical | `proc.name in (nsenter, chroot)` sau `unshare --mount` — pașii 4, 5, 6 |
| `K8S_THREAT: Sensitive File Read in Container` | custom | Warning | `chroot /host` apoi `head /etc/shadow` → path-ul rezolvă la `/etc/shadow` (host-ului) — pasul 5 (bonus) |
| `Drop and execute new binary in container` | default | Critical | improbabil — nsenter/chroot/unshare sunt în base image |
| (default escape rules: `Change thread namespace`, etc.) | default | varies | posibil pe `nsenter`/`unshare` (setns/unshare syscalls) |

## Rezultate finale (helm rev 25)

### Falco — 13 detecții (toate true positive, 0 FP)

| Regulă | Tip | Priority | Count | Generată de |
|---|---|---|---|---|
| `K8S_THREAT: Container Escape - Nsenter or Chroot Usage` | custom | Critical | 9 | `nsenter -t 1 ...` (×4 — nsenter face fork+re-exec pentru namespace-ul PID), `chroot /host ...` (×1), `unshare --mount --fork ...` (×4) — pașii 4, 5, 6 |
| `K8S_THREAT: Container Escape - Sensitive Mount Access` | custom | Critical | 2 | `head /proc/sysrq-trigger` (pasul 2), `cat /run/containerd/containerd.sock` (pasul 3) |
| `K8S_THREAT: Sensitive File Read in Container` | custom | Warning | 1 | `head -1 /etc/shadow` după `chroot /host` → path-ul rezolvă la `/etc/shadow` al **host-ului** (output: `root:*:19998:...`, epoch diferit de cel al containerului) — pasul 5 (bonus) |
| `Read sensitive file untrusted` | default | Warning | 1 | aceeași citire `/etc/shadow` (host) — confirmare cross-rule |
| **Total Falco** | | | **13** | |

### Bilanț detecție

| Step | Detectat? | Prin ce |
|---|---|---|
| 1 — deploy escape-pod (privileged, hostPID, hostPath /, containerd.sock) | ❌ NU de Falco | acțiune K8s API; `Launch Privileged Container`/`Launch Sensitive Mount Container` neactive, `k8saudit` neactivat — vezi observația #1 |
| 2 — `head /proc/sysrq-trigger` | ✅ DA | `Container Escape - Sensitive Mount Access` |
| 3 — `cat /run/containerd/containerd.sock` | ✅ DA | `Container Escape - Sensitive Mount Access` |
| 4 — `nsenter -t 1 ...` (host namespaces) | ✅ DA | `Container Escape - Nsenter or Chroot Usage` ×4 |
| 5 — `chroot /host` + citire host `/etc/shadow` | ✅ DA | `Container Escape - Nsenter or Chroot Usage` + `Sensitive File Read in Container` + `Read sensitive file untrusted` |
| 6 — `unshare --mount` | ✅ DA | `Container Escape - Nsenter or Chroot Usage` ×4 |

**Detection rate (pași cu alertă)**: 5/5 = 100% (pasul 1 — deployment-ul în sine — nedetectat, în afara perimetrului runtime; vezi mai jos).
**False positive rate**: 0%.

> _Notă: `container_name` apare ca ID-ul de container (`c4cc204bf804`) în loc de numele k8s (`escaper`) — aceeași inconsistență a plugin-ului `container@0.6.3` ca la celelalte scenarii (vezi `03-reverse-shell`); `k8s.ns.name`/`k8s.pod.name` corecte._

## Procesul de tuning

| Iterație | Modificare | Total | True+ | False+ |
|---|---|---|---|---|
| A (baseline, helm rev 25) | reguli existente | 13 | 13 | 0 |

**0 iterații de tuning necesare** — regulile de container escape acoperă complet tehnicile testate, fără fals-pozitive.

## Re-validare pe helm rev 30 (2026-06-18)

**Rezultate identice** cu baseline-ul rev 25: **13 detecții, 0 FP** — `Container Escape - Nsenter or
Chroot Usage` ×9 (nsenter ×4, chroot ×1, unshare ×4), `Container Escape - Sensitive Mount Access` ×2
(`/proc/sysrq-trigger`, `/run/containerd/containerd.sock`), `Sensitive File Read in Container` ×1 +
`Read sensitive file untrusted` ×1 (host `/etc/shadow`, epoch `19998`). Niciun set FIM nou (rev 30) nu
s-a declanșat (escape-ul nu scrie în `/etc` sau binar dirs — doar citește).

## Observații așteptate (de validat)

1. **Deployment-ul escape-pod-ului (pasul 1) — nedetectat de Falco** — la fel ca la scenariul 8: crearea unui pod privilegiat e o acțiune K8s API; regulile `Launch Privileged Container`/`Launch Sensitive Mount Container` nu sunt active, `k8saudit` nu e activat. Falco prinde *consecințele* (pașii 2-6), nu *configurația greșită* care le permite. **Lecție**: defense in depth cere și un layer de policy/admission (Cap 6) — analiză detaliată + mapare pe scenarii în `docs/admission-control-recommendation.md`.

2. **Path matching depinde de cum e montat host-ul** — regula `Sensitive Mount Access` verifică `fd.name startswith /run/containerd/containerd.sock` etc. Funcționează doar dacă path-ul în container coincide cu cel de pe host. Am montat socket-ul exact la `/run/containerd/containerd.sock` (nu la `/host/run/...`) tocmai ca regula să facă match — un atacator care montează host-ul la un prefix arbitrar (`/host`, `/mnt`) ar evita match-ul pe path. Citirea `/host/etc/shadow` (prefix `/host`) NU declanșează `Sensitive File Read` (regula verifică `fd.name = /etc/shadow` exact). **Limitare structurală**: regulile bazate pe path absolut nu acoperă mount-uri la prefixe arbitrare. `chroot /host` apoi `/etc/shadow` ESTE prins pentru că chroot schimbă rezoluția de path → kernel-ul vede `/etc/shadow`.

3. **Detecție pe tool (`nsenter`/`chroot`/`unshare`)** — robustă pentru tehnicile clasice de breakout, dar un atacator poate face syscall-urile direct (`setns(2)`, `unshare(2)`) dintr-un binar custom fără a invoca tool-urile cu acele nume. Regulile default Falco pe `setns`/`unshare` syscalls (dacă active) ar complementa. De verificat ce trage la pasul 4/6.

4. **`/proc/sysrq-trigger` accesibil chiar fără mount-uri** — e o interfață kernel globală (nu namespaced); orice container privilegiat o poate deschide. Detecția pe open() e corectă, dar zgomotoasă potențial dacă vreun proces de sistem legitim o atinge (de monitorizat — `kubelet`, `systemd`?).

## Suricata
N/A — toate acțiunile sunt locale (filesystem, namespace, syscalls). Fără trafic de rețea relevant.

## False negatives potențiale

- **Mount host la prefix arbitrar** (`/host`, `/mnt/host`) — `Sensitive Mount Access` și `Sensitive File Read` ratează (path nu coincide). Vezi #2.
- **Escape via syscall direct** (`setns`/`unshare` dintr-un binar compilat, fără tool-urile `nsenter`/`unshare`) — `Nsenter or Chroot Usage` ratează (verifică `proc.name`). Default rules pe syscalls ar ajuta.
- **Escape via `release_agent` cgroup** (clasicul SYS_ADMIN breakout: `mount -t cgroup ...; echo /path > release_agent; ...`) — nicio regulă custom; ar trebui o regulă pe `mount` syscall cu `cgroup` + scriere în `release_agent`.
- **Escape via vulnerabilitate kernel** (CVE de privilege escalation/breakout) — nedetectabil cu reguli statice de syscall/path.
- **Escape via Kubernetes RBAC abuse** (token ServiceAccount cu permisiuni de a crea pod-uri privilegiate) — prins parțial la scenariul 4 (citire token) + ar fi prins de `k8saudit` la `CREATE pod` (neactiv).
