# Scenariul 9 — OWASP ZAP (DAST scan vs DVWA)

**MITRE ATT&CK:** T1595.002 (Active Scanning: Vulnerability Scanning), T1190 (Exploit Public-Facing Application), T1046 (Network Service Discovery). Tactici: Reconnaissance / Initial Access.

## Idee

`OWASP ZAP` rulat în mod `zap-full-scan.py` (spider + AJAX spider + **active scan**) împotriva pod-ului DVWA. Aruncă payload-uri reale de atac web (SQLi, PHP RFI, code injection, path traversal, …) la nivel HTTP. Scenariu **dominat de Suricata** — atacul e pur la nivel aplicativ web, vizibil pe rețea. E **polul opus al lui s10** (kube-hunter, dominat de Falco): împreună demonstrează cele două straturi complementare — NIDS pe trafic (s09) vs runtime host-based (s10).

> Acest scenariu a scos la iveală **două probleme de configurare** ale stratului Suricata (vezi „Procesul de tuning"). După corectarea lor, detecția a trecut de la **0 semnături de atac web** la **~208 alerte ET WEB_SERVER de signature** (187 de severitate HIGH) pe același scan — material central pentru Cap D.

## Execuție

Job `zap-scan` (namespace `attack-target`, manifest `zap-scan-job.yaml`), image `ghcr.io/zaproxy/zaproxy:stable` (~1.3 GB, **pre-pull necesar** — vezi mai jos), pinned pe **node-4** (atacator „remote"). Țintă: pod-ul DVWA `http://10.1.139.66` (node-3). După adăugarea unui sensor Suricata și pe node-3 (vezi obs. #2), atacul e prins de **senzorul node-3** (lângă țintă) indiferent de nodul atacatorului. *(Inițial, când exista sensor doar pe node-2, ZAP trebuia pe node-2 — vezi istoricul din obs. #2.)*

**De ce node-4 (atacator remote) merge acum** (vezi obs. #2): există un sensor Suricata pe **node-3** (lângă DVWA). Un sensor capturează doar traficul de pe `ens3`-ul nodului său, dar traficul de atac ajunge la DVWA **pe `ens3`-ul node-3** (decapsulat din VXLAN), deci senzorul node-3 îl prinde indiferent de nodul atacatorului. Plasăm ZAP pe node-4 tocmai ca să demonstrăm cazul „atacator pe alt nod decât ținta".

> **Pre-pull** (o singură dată, imaginea e mare pe discul lent): aplică un Job tranzitoriu cu aceeași imagine pe node-4 înainte de prima rulare. Ulterior imaginea e cache-uită pe nod.

## Rezultate finale (rulare 2026-05-31, **după** fix-ul HOME_NET — iterația B aplicată)

> Numerele de mai jos (~208 alerte ET, 187 HIGH) sunt din rularea care a **demonstrat fix-ul HOME_NET**, cu ZAP pe node-2 prins de senzorul node-2. Rularea ulterioară de **validare a topologiei** (ZAP pe node-4, prins de senzorul node-3) a dat 21 alerte ET WEB_SERVER — aceleași tipuri de atac, count mai mic din reasamblare peste VXLAN; vezi obs. #2.

### Raportul ZAP (ce a găsit DAST-ul în DVWA)

| Rezultat | Count | Exemple |
|---|---|---|
| **PASS** (reguli active fără finding) | 130 | SQLi, XSS, RCE, SSTI, Log4Shell, XXE — PASS pentru că paginile vulnerabile DVWA sunt **în spatele login-ului** |
| **WARN-NEW** (config / info disclosure) | 12 categorii | X-Content-Type-Options Missing ×5, Server Leaks Version ×9, Cookie No HttpOnly ×6, Cookie no SameSite ×6, Directory Browsing ×3, CSP Not Set ×2, … |
| **FAIL-NEW** | 0 | niciun exploit confirmat (zid de autentificare) |

> Un DAST **neautentificat** scoate la iveală igiena de securitate, nu SQLi/XSS-ul din spatele auth-ului. **Important**: deși ZAP raportează PASS (nu confirmă exploatare), active scan-ul **trimite efectiv payload-urile** (SQLi/RFI/PHP în body-uri POST către login.php etc.) — iar acestea sunt **prinse de Suricata pe fir** chiar dacă DVWA le respinge. Asta e exact valoarea cross-tool: NIDS-ul vede *tentativa*, indiferent de rezultatul aplicativ.

### Suricata — 534 alerte, din care ~208 semnături ET de atac web

| Severitate | Count |
|---|---|
| 1 (HIGH) | 187 |
| 2 (medium) | 18 |
| 3 (low — anomaly engine) | 329 |

**Semnături ET WEB_SERVER / HUNTING declanșate (NOU după fix):**

| Semnătură | Count | Tip atac |
|---|---|---|
| ET WEB_SERVER Possible SQL injection WAITFOR DELAY in HTTP Request Body | 30 | SQLi (time-based) |
| ET WEB_SERVER PHP tags in HTTP POST | 24 | PHP code injection |
| ET WEB_SERVER allow_url_include PHP config option in uri | 24 | PHP RFI / LFI |
| ET WEB_SERVER auto_prepend_file PHP config option in uri | 24 | PHP RFI / LFI |
| ET WEB_SERVER PHP.//Input in HTTP POST | 23 | PHP wrapper injection |
| ET WEB_SERVER Generic PHP Remote File Include | 19 | RFI |
| ET HUNTING Suspicious PHP Code in HTTP POST (Out/Inbound) | 14 / 13 | code injection |
| ET WEB_SERVER Possible SQL Injection (exec) in HTTP Request Body | 11 | SQLi (exec) |
| ET WEB_SERVER PHP Possible php Remote File Inclusion Attempt | 4 | RFI |
| ET WEB_SERVER Tilde in URI - potential .php~ source disclosure | 1 | source disclosure |
| ET INFO Proxy TRACE Request / Dotted Quad ZIP / python-requests UA / Googlebot UA | 15 / 3 / 2 / 1 | scanner fingerprint |

**Anomaly engine (severity 3), persistă din baseline:** SURICATA STREAM 3way handshake wrong seq/ack ×98, HTTP Response excessive header repetition ×65, HTTP unable to match response to request ×63, STREAM invalid timestamp/ack ×65, etc.

**Telemetrie ne-alertă:** `http` 1269, `fileinfo` 1189, `flow` 578, `dns` 180, `anomaly` 161, `tls` 51.

src/dest: ZAP pod `10.1.247.54` ↔ DVWA `10.1.139.66` (287 / 230 alerte pe direcție).

### Falco — pod-ul ZAP, DVWA tăcut

`zap-scan-*` = 71 evenimente (Drop&execute pe procesele java/python ale ZAP + PTRACE de la JVM — incidental). **DVWA pod = 0** (niciun exec server-side, scan neautentificat). Cele 146× `Kubernetes Secret Access` + 120× `Sensitive File Read` din interogarea brută sunt **zgomot de background** de la `prometheus-server` (251 ev.) — filtrate, nu aparțin scenariului (vezi s11 obs. #3).

## Bilanț cross-tool (după fix)

| Strat | A văzut | A detectat |
|---|---|---|
| **Suricata (NIDS)** | TOT (1269 HTTP tx, 1189 fileinfo) | **534 alerte: ~208 semnături ET de atac web specific (SQLi/RFI/PHP injection) + ~326 anomalii engine** |
| **Falco (runtime)** | doar procesele din pod-uri | 71 pe pod-ul ZAP (binarul scanner) — **orb la atacul aplicativ** |
| **ZAP (atacatorul)** | aplicația web | 12 categorii de probleme reale în DVWA |

**Detection rate (Suricata):** scanul e detectat cu fidelitate înaltă — ET atribuie *tipul* de atac (SQLi vs RFI vs source disclosure), nu doar „ceva anormal".

## Procesul de tuning (2 iterații)

| Iterație | Stare Suricata | Alerte signature web | Constatare |
|---|---|---|---|
| **A (baseline)** | ET Open încărcat, dar `HOME_NET = [10.11/16, 10.102/16]` (doar rețele de noduri) | **0** | toate cele 805 alerte erau **anomaly engine**; semnăturile ET (scope `$HTTP_SERVERS=$HOME_NET`) nu evaluau traficul de pod |
| **B (aplicată 2026-05-31)** | `HOME_NET += 10.1.0.0/16 (pod CIDR) + 10.152.183.0/24 (svc CIDR)`; `EXTERNAL_NET = any` | **~208** | ET WEB_SERVER se declanșează pe ZAP→DVWA; 187 alerte HIGH |

Fix-ul aplicat pe **node-2** (`/etc/suricata/suricata.yaml`, apoi `suricata -T` + `systemctl restart suricata`). **Nicio regulă scrisă** — capacitatea de detecție exista deja (63.800 reguli ET încărcate, 8.123 web); doar perimetrul `HOME_NET` o ținea oarbă.

## Observații (Cap D / Cap 6)

1. **Root cause: HOME_NET nu acoperea rețeaua de workload-uri (pod CIDR).** Suricata avea **ET Open complet încărcat** (63.800 reguli, 8.123 web) — dar `HOME_NET` era scope-uit **doar pe rețelele de noduri/VM** (`10.11.0.0/16`, `10.102.0.0/16`), excluzând CIDR-ul Calico de pod-uri (`10.1.0.0/16`) și pe cel de servicii (`10.152.183.0/24`). Cum `HTTP_SERVERS = $HOME_NET` și regulile ET web sunt `$EXTERNAL_NET -> $HTTP_SERVERS`, **nicio semnătură nu evalua traficul intra-cluster** (pod→pod e complet în afara perimetrului). IDS-ul „vedea" pachetele (parsa HTTP-ul → telemetrie) dar nu le „judeca" cu semnăturile. Fix: extinderea `HOME_NET` cu CIDR-urile clusterului + `EXTERNAL_NET = any` (ca un pod-atacator, acum intern, să mai poată fi „extern" pentru reguli). **Aceasta e cea mai importantă lecție de configurare a tezei**: un IDS de cluster e inutil dacă `HOME_NET` nu include rețeaua de pod-uri/servicii — o capcană ușor de ratat, pentru că engine-ul de anomalie *tot* produce alerte și dă falsa impresie că „merge".

2. **Topologie de captură single-node — descoperit ȘI rezolvat.** *Descoperire (2026-05-31):* un sensor Suricata vede **doar traficul de pe NIC-ul (`ens3`) al nodului său**. Cu sensor doar pe node-2: ZAP pe node-4 → DVWA node-3 = **0 HTTP / 0 alerte**; ZAP pe node-2 → DVWA node-3 = **1269 HTTP / 534 alerte**. Un deployment pe un singur nod e un IDS *parțial*. *Rezolvare:* am adăugat un **sensor systemd și pe node-3** (nodul de aplicații). Principiul cheie: **senzorul stă lângă ȚINTĂ, nu lângă atacator** — traficul de atac ajunge pe `ens3`-ul nodului-țintă (decapsulat din VXLAN) și e prins indiferent de unde e atacatorul. *Validat:* ZAP pe node-4 → DVWA node-3 = **21 alerte ET WEB_SERVER, toate atribuite senzorului `node-3`** (0 de pe node-2). Arhitectura finală: sensori pe **node-2 + node-3**; **NU pe node-4** (nodul ELK — co-locarea IDS cu log store-ul e anti-pattern: resource contention + single point of failure; node-4 e high-value target protejat de Falco + access control); NU pe node-1 (control-plane). Acoperire cluster-wide completă (Suricata DaemonSet, ca Falco) = direcție Cap E. Detalii: `suricata/systemd-sensors/README.md`.

3. **Falco e structural orb la atacul web neautentificat.** DVWA n-a generat niciun eveniment Falco — un scan neautentificat nu declanșează execuție server-side (paginile vulnerabile sunt după login). Dacă ZAP ar fi autentificat și ar exploata Command Injection-ul DVWA, `apache`/`php` ar face `system()` → Falco ar prinde shell-ul (domeniul s03). Demarcație: **Falco prinde consecința unui exploit reușit la runtime; Suricata prinde tentativa la nivel rețea.**

4. **ZAP raportează PASS, dar Suricata îl prinde.** Discrepanța e instructivă: ZAP nu *confirmă* vulnerabilitatea (DVWA respinge payload-urile neautentificate), deci raportează PASS — dar *trimite* payload-urile pe fir, unde Suricata le detectează prin signature. Un atacator nu trebuie să *reușească* pentru a fi *detectat* — modelul „intent vs success" recurent (vezi s03, s11).

## False negatives potențiale

- **Atac web peste HTTPS** — dacă DVWA ar fi pe TLS, Suricata ar vedea doar handshake-ul (ca în s11), nu URI-ul/body-ul → semnăturile web n-ar funcționa fără TLS interception. Limitare a NIDS-ului pe trafic criptat. Aici DVWA e HTTP simplu.
- **Atac către o țintă de pe un nod fără sensor Suricata** (vezi obs. #2) — sensori avem pe node-2 + node-3. Un atac către un pod aflat pe node-1 sau node-4 (ținta pe un nod fără sensor) ar fi invizibil pentru Suricata (rămâne acoperit de Falco la runtime). Mitigare pentru acoperire totală de rețea = sensor per nod (DaemonSet).
- **Atac „low and slow" / payload-uri encodate** sub semnăturile ET — un scanner care evită pattern-urile cunoscute (ofuscare, encoding neacoperit) ar scăpa de semnături; ar rămâne doar anomaliile de stream (low-fidelity).
