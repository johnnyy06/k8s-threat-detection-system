# Suricata — starea reală pe cluster (node-2)

Suricata rulează ca **serviciu systemd pe node-2** (nodul „security"), NU ca pod. ELK e pe node-4 — a nu se confunda. Acest repo doar **oglindește parțial** configul; sursa de adevăr e pe node-2.

## Ce e efectiv încărcat (verificat 2026-05-31, Suricata 8.0.3)

- **Rule path:** `/var/lib/suricata/rules/suricata.rules` — **63.800 reguli** (ET Open complet, livrat cu pachetul Suricata din `/usr/share/suricata/rules`, agregat de `suricata-update`). Din care **8.123 reguli web** (SQLi/XSS/WEB_SERVER/WEB_SPECIFIC).
- `rule-files:` în `/etc/suricata/suricata.yaml` listează doar `suricata.rules` (NU `suricata-local.rules`).
- **`suricata-update list-enabled-sources` = „No enabled sources"** — dar regulile ET tot se încarcă (cele provided cu pachetul). Pentru update-uri live: `sudo suricata-update enable-source et/open && sudo suricata-update`.

> ⚠️ **`rules/suricata-local.rules` din acest repo e STALE și NU e încărcat pe node-2** (fișierul nici nu există acolo). E un artefact istoric (15 reguli custom: port scan, SSH brute, K8s API, reverse shell). Dacă vrei reguli locale live, adaugă-le într-un fișier referențiat din `rule-files:` și restart.

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

## Topologie de captură single-node — descoperit & rezolvat

Suricata pe un nod vede **doar traficul de pe NIC-ul (`ens3`) al nodului său** (workload-urile de pe el + traficul către/de la el), NU trafic arbitrar inter-node. Demonstrat empiric: cu sensor doar pe node-2, ZAP pe node-4 → DVWA node-3 = **0 alerte**; ZAP pe node-2 → DVWA node-3 = **534 alerte**.

**Rezolvare (2026-05-31):** am adăugat un **sensor systemd și pe node-3** (nodul de aplicații, unde sunt țintele). Principiul: **senzorul stă lângă ȚINTĂ, nu lângă atacator** — traficul de atac ajunge pe `ens3`-ul nodului-țintă (decapsulat din VXLAN) și e prins indiferent de nodul atacatorului. Validat: ZAP pe node-4 → DVWA node-3 = **21 alerte ET WEB_SERVER atribuite senzorului node-3**.

**Arhitectura finală:** sensori pe **node-2 + node-3** (nodurile cu workload-uri/ținte). **NU pe node-4** (ELK — co-locarea IDS cu log store-ul e anti-pattern: resource contention pe disk-bottlenecked node + single point of failure + node-4 e high-value target protejat mai bine de Falco + access control). **NU pe node-1** (control-plane). Detalii + runbook: `systemd-sensors/README.md`. Varianta cloud-native (Suricata ca **DaemonSet** declarativ pe nodurile etichetate, ca Falco) a fost evaluată dar nu aleasă — pe un cluster fix cu disk I/O bottleneck, systemd-ul e mai simplu/low-risk; rămâne ca direcție de optimizare (Cap E).
