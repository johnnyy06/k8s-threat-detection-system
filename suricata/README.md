# Suricata — starea reală pe cluster (node-2)

Suricata rulează ca **serviciu systemd pe node-2** (nodul „security"), NU ca pod. ELK e pe node-4 — a nu se confunda. Acest repo doar **oglindește parțial** configul; sursa de adevăr e pe node-2.

## Ce e efectiv încărcat (verificat 2026-05-31, Suricata 8.0.3)

- **Rule path:** `/var/lib/suricata/rules/suricata.rules` — **63.800 reguli** (ET Open complet, livrat cu pachetul Suricata din `/usr/share/suricata/rules`, agregat de `suricata-update`). Din care **8.123 reguli web** (SQLi/XSS/WEB_SERVER/WEB_SPECIFIC).
- `rule-files:` în `/etc/suricata/suricata.yaml` listează doar `suricata.rules` (NU `suricata-local.rules`).
- **`suricata-update list-enabled-sources` = „No enabled sources"** — dar regulile ET tot se încarcă (cele provided cu pachetul). Pentru update-uri live: `sudo suricata-update enable-source et/open && sudo suricata-update`.

## Reguli locale custom — LIVE (2026-06-14)

`rules/suricata-local.rules` e acum **încărcat pe ambele noduri** (deployat în
`/var/lib/suricata/rules/suricata-local.rules`, adăugat în `rule-files:` din `suricata.yaml`,
înaintea/lângă `suricata.rules`; `suricata-update` NU-l atinge). Cele 4 reguli stale vechi
(port scan / SSH brute / K8s API / reverse shell) au fost **retrase** — erau redundante cu ET Open.

**Decizie (Cap C/D):** ET Open (~63.8k reguli, mentenanțat) = baza, conform practicii din industrie;
regulile locale **complementează** doar pe gap-uri K8s-specifice reale, legate de scenariile de atac:

| SID | Detecție | MITRE | Gap acoperit |
|---|---|---|---|
| 1000010 | Acces cloud metadata IMDS `169.254.169.254` | T1552.005 | s10 (kube-hunter KHV053); IMDS real pe OpenStack |
| 1000011 | Token SA/JWT `Bearer eyJ` pe HTTP necriptat | T1552.001 | s11 (lateral movement) — token expus în clar |
| 1000012 | Exfiltrare DNS — etichetă query 50+ caractere | T1048.003 | s07 (DNS exfil) — complement network-side la Falco |

**Validate live (2026-06-14):** toate 3 trag — 1000010 (→169.254.169.254), 1000011 (attack-pod→DVWA,
**inter-nod** obligatoriu: intra-nod e Suricata-blind), 1000012 (pod→CoreDNS→upstream, node-2+node-3).
Reload după editare: `sudo suricata -T -c /etc/suricata/suricata.yaml` apoi `systemctl restart suricata`
(o schimbare în `rule-files:` necesită restart, nu doar reload USR2). Count reguli: node-2 47964→47967.

## Fix critic de config — HOME_NET (iterația B s09, aplicat 2026-05-31)

**Problemă (root cause):** `HOME_NET` era scope-uit doar pe rețelele de noduri/VM, excluzând CIDR-ul de pod-uri și de servicii. Cum `HTTP_SERVERS = $HOME_NET` și regulile ET web sunt `$EXTERNAL_NET -> $HTTP_SERVERS`, **nicio semnătură nu evalua traficul intra-cluster (pod→pod)**. Rezultat: scanuri web (s09 ZAP) detectate doar prin anomaly engine, 0 semnături.

**Fix aplicat în `/etc/suricata/suricata.yaml` (vars):**
```yaml
# înainte:
#   HOME_NET: "[10.11.0.0/16,10.102.0.0/16]"
#   EXTERNAL_NET: "!$HOME_NET"
# după:
HOME_NET: "[10.11.0.0/16,10.102.0.0/16,10.1.0.0/16,10.152.183.0/24]"   # + pod CIDR + svc CIDR
EXTERNAL_NET: "any"                                                     # ca pod-atacatorul (intern) sa mai fie "extern"
```
Apoi: `sudo suricata -T -c /etc/suricata/suricata.yaml` (test) + `sudo systemctl restart suricata`.

**Efect (validat):** s09 (ZAP vs DVWA) a trecut de la **0 semnături web** la **~208 alerte ET WEB_SERVER** (187 HIGH: SQLi WAITFOR DELAY, PHP RFI, PHP code injection, source disclosure). Detalii în `attack-scenarios/09-owasp-zap/expected-detections.md`.

## Logrotate eve.json — bug găsit & reparat (2026-06-13)

Suricata NU rotește singur log-urile; depinde de `logrotate` (rulează zilnic via `logrotate.timer`).
La inspecție: **node-2 nu avea deloc `/etc/logrotate.d/suricata`** → `eve.json` ajunsese la **25,6 GB**
(+ `stats.log` 14,6 GB) ≈ 40 GB pe un cluster cu disk I/O bottleneck. **node-3 avea un config dar
îl sărea** cu `error: skipping ... parent directory has insecure permissions ... Set "su" directive`
— logrotate modern refuză să rotească `/var/log/suricata` (deținut de `suricata:suricata`, nu root)
fără directiva **`su`**.

**Fix (ambele noduri):** `systemd-sensors/logrotate-suricata.conf` → `/etc/logrotate.d/suricata`,
cu `su suricata suricata` + `copytruncate` (Suricata își păstrează fd-ul; compatibil cu Filebeat) +
`daily`/`rotate 7`/`maxsize 2G`/`compress`. Verificare: `sudo logrotate -dv /etc/logrotate.d/suricata`
(fără erori de permisiuni). Recuperare imediată a unui eve.json deja uriaș (datele sunt deja în ES):
`sudo truncate -s 0 /var/log/suricata/{eve.json,stats.log,fast.log}` → node-2 a coborât 65%→17% disc.

> Notă: `stats.log`/`fast.log` NU se shippează (Filebeat citește doar `eve.json`) — truncare 100% sigură.

## Topologie de captură single-node — descoperit & rezolvat

Suricata pe un nod vede **doar traficul de pe NIC-ul (`ens3`) al nodului său** (workload-urile de pe el + traficul către/de la el), NU trafic arbitrar inter-node. Demonstrat empiric: cu sensor doar pe node-2, ZAP pe node-4 → DVWA node-3 = **0 alerte**; ZAP pe node-2 → DVWA node-3 = **534 alerte**.

**Rezolvare (2026-05-31):** am adăugat un **sensor systemd și pe node-3** (nodul de aplicații, unde sunt țintele). Principiul: **senzorul stă lângă ȚINTĂ, nu lângă atacator** — traficul de atac ajunge pe `ens3`-ul nodului-țintă (decapsulat din VXLAN) și e prins indiferent de nodul atacatorului. Validat: ZAP pe node-4 → DVWA node-3 = **21 alerte ET WEB_SERVER atribuite senzorului node-3**.

**Arhitectura finală:** sensori pe **node-2 + node-3** (nodurile cu workload-uri/ținte). **NU pe node-4** (ELK — co-locarea IDS cu log store-ul e anti-pattern: resource contention pe disk-bottlenecked node + single point of failure + node-4 e high-value target protejat mai bine de Falco + access control). **NU pe node-1** (control-plane). Detalii + runbook: `systemd-sensors/README.md`. Varianta cloud-native (Suricata ca **DaemonSet** declarativ pe nodurile etichetate, ca Falco) a fost evaluată dar nu aleasă — pe un cluster fix cu disk I/O bottleneck, systemd-ul e mai simplu/low-risk; rămâne ca direcție de optimizare (Cap E).
