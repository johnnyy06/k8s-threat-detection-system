# Scenariul 10 — kube-hunter (K8s pentest / recon insider)

**MITRE ATT&CK:** T1613 (Container & Resource Discovery), T1046 (Network Service Discovery), T1552.001 (Unsecured Credentials: SA token), T1550.001 (Use of App Access Token). Tactici: **TA0007 Discovery** + Credential Access.

## Idee

`kube-hunter` (Aqua Security) e un tool de penetration testing pentru Kubernetes. Rulat în mod **`--pod --active`** simulează un atacator care a obținut deja execuție într-un pod și „vânează" din interiorul clusterului: descoperă serviciile K8s deschise (API server, kubelet), citește și testează token-ul ServiceAccount, scanează subnet-ul de pod-uri (raw sockets / ARP), sondează API-ul de cloud metadata și rulează o baterie de teste de vulnerabilități K8s (KHV*).

Scenariu **dominat de Falco** — recon-ul K8s-native se vede la nivel runtime (citiri de secrete, conexiune la API, packet sockets). E complementar cu s09 (ZAP, dominat de Suricata): împreună demonstrează cele două capete ale spectrului — recon de infrastructură (Falco) vs atac aplicativ web (Suricata).

## Execuție

Job `kube-hunter` (namespace `attack-target`, manifest `kube-hunter-job.yaml`), image `aquasec/kube-hunter:latest` (~180 MB), pinned pe **node-4** (lângă attack-pod; Falco e DaemonSet pe toate nodurile deci detectează indiferent de plasare). Args: `--pod --active --report yaml`. Job-ul se auto-curăță (`ttlSecondsAfterFinished`).

## Ce a descoperit kube-hunter (raportul atacatorului)

| VID | Vulnerabilitate | Severitate | Categorie | Real? |
|---|---|---|---|---|
| KHV050 | Read access to pod's service account token | low | Credential Access | ✅ da (token montat) |
| — | CAP_NET_RAW Enabled | medium | Lateral Movement (ARP/IP spoofing) | ✅ da (default pe pod-uri) |
| — | Access to pod's secrets | low | Credential Access | ✅ da (enumeră `/var/run/secrets/...`) |
| KHV053 | AWS Metadata Exposure | high | Discovery (Instance Metadata API) | ❌ **fals pozitiv** (vezi obs. #3) |

## Rezultate finale (helm rev 26, rulare 2026-05-30)

### Falco — 14 detecții (filtrate pe pod-ul `kube-hunter-*`), toate true positive

| Regulă | Tip | Priority | Count | Generată de |
|---|---|---|---|---|
| `K8S_THREAT: Sensitive File Read in Container` | custom | Warning | 7 | citirea fișierelor din `/var/run/secrets/kubernetes.io/serviceaccount/` (ca.crt, namespace, dir, token-path) — hunter-ul „Access Secrets" |
| `Packet socket created in container` | default | Notice | 4 | `AF_PACKET` raw sockets (CAP_NET_RAW) pentru ARP/host discovery — **corelează cu finding-ul kube-hunter „CAP_NET_RAW Enabled"** |
| `K8S_THREAT: Kubernetes Secret Access from Pod` | custom | Notice | 2 | citirea `.../serviceaccount/token` de către procesul `kube-hunter` |
| `Contact K8S API Server From Container` | default | Notice | 1 | conexiune `10.1.217.76 → 10.152.183.1:443` (probe API server) — overlap cu s11 |
| **Total** | | | **14** | |

**Detection rate:** toate cele 3 acțiuni observabile la runtime (token/secret read, API contact, packet sockets) sunt detectate. **False positive rate (Falco):** 0.

### Suricata
**0 alerte de signature (depasit, explicat in revalidare rev 30)**, din două motive cumulate: (a) probe-ul către API server e HTTPS (TLS:443) → conținut criptat, niciun signature; scanarea de subnet via raw sockets (ARP/SYN) e recon, nu exploit cu payload cunoscut; și (b) **kube-hunter rulează pe node-4, iar sensorul Suricata e pe node-2 și vede doar traficul nodului său** (vezi s09 obs. #2) → traficul kube-hunter nici n-ar fi capturat. Indiferent de plasare, pentru recon K8s-native **Falco e detectorul, Suricata doar martorul de telemetrie** (și aici, nici măcar martor, dat fiind nodul). Confirmă concluzia: detecția lateral/recon K8s-native e treaba runtime-ului host-based.

## Re-validare pe helm rev 30 (2026-06-18) — kube-hunter pe node-2, gap-ul de metadata ACUM acoperit

> **Pinning actual:** manifestul `kube-hunter-job.yaml` pinează acum **node-2** (nu node-4 ca în textul de
> mai jos, care e istoric). node-2 are senzor Suricata → traficul de recon e parțial vizibil pe rețea.

- **Falco: 14 evenimente — identic cu baseline-ul rev 26** (filtrat pe pod-ul `kube-hunter-*`):
  `Sensitive File Read` ×7, `Packet socket created` ×4, `Kubernetes Secret Access` ×2,
  `Contact K8S API Server` ×1. Detecție stabilă (Falco e DaemonSet, plasarea nu contează).
- **Raport kube-hunter identic:** CAP_NET_RAW Enabled, KHV050 (SA token read), Access to pod's secrets,
  KHV053 AWS Metadata Exposure (tot FP al tool-ului — on-prem, 404 de la 169.254.169.254).
- **Suricata — SCHIMBARE: gap-ul de cloud-metadata din obs. #3 e ACUM ACOPERIT.** kube-hunter pe node-2
  (nod cu senzor) sondează `169.254.169.254` → **regula custom Suricata `K8S-LOCAL Cloud Metadata Service
  Access Attempt (IMDS 169.254.169.254)` (sid 1000010, T1552.005) se declanșează ×1**. Plus 3× anomalie
  HTTP (zgomot). Deci „gap-ul de detecție" notat în obs. #3 (acces 169.254.169.254 neacoperit) **nu mai e
  un gap la nivel NIDS** — regula custom deployată în `suricata/rules/suricata-local.rules` (live din
  2026-06-14) îl prinde. Două condiții au făcut-o vizibilă: (1) kube-hunter rulează pe un nod cu senzor
  (node-2), (2) regula custom există. Pe node-4 (vechea plasare) ar fi rămas Suricata-blind.
- **Cross-validare nouă:** kube-hunter *raportează* „AWS Metadata Exposure" (FP al euristicii lui, on-prem)
  iar Suricata *detectează* concret tentativa de acces IMDS — tool-ul ofensiv și detectorul converg pe
  același IoC (chiar dacă verdictul tool-ului e greșit, *tentativa* e reală și acum detectată).

## Observații (Cap D / Cap 6)

1. **Corelație tool-atacator ↔ detector — `CAP_NET_RAW` / packet sockets.** kube-hunter raportează „CAP_NET_RAW Enabled" (capabilitatea care permite ARP poisoning între pod-uri pe același nod), iar Falco prinde *consecința* operațională: 4× `Packet socket created in container` (`domain=17 AF_PACKET`). Aceasta e o validare încrucișată elegantă — ceea ce tool-ul ofensiv *identifică* ca slăbiciune, stratul defensiv îl *detectează* în execuție. Material bun pentru Cap D (demonstrație că detecția runtime surprinde primitive low-level pe care un scanner de config doar le inferă).

2. **Citirea token-ului SA = semnal recurent de credential access.** kube-hunter face exact ce face un atacator real în faza de discovery: enumeră `/var/run/secrets/kubernetes.io/serviceaccount/` și citește token-ul. Cele 7× `Sensitive File Read` + 2× `Kubernetes Secret Access` confirmă că regulile custom acoperă atât tool-uri manuale (s04, s11: `cat`) cât și tool-uri automate (kube-hunter) — regula se uită la *fișierul accesat*, nu la *cine* îl accesează. Overlap intenționat cu s04/s11.

3. **Fals pozitiv în raportul kube-hunter — „AWS Metadata Exposure" (KHV053, high).** kube-hunter a încercat să contacteze API-ul de cloud metadata (`169.254.169.254`) și a primit un **404 HTML** pe care euristica lui l-a interpretat greșit drept „expunere". Clusterul e **on-prem (VM-uri facultate), nu AWS** → nu există metadata service real. E un FP al *tool-ului ofensiv*, nu al sistemului nostru de detecție — dar e o lecție utilă: severitatea raportată de un scanner automat trebuie validată contextual (aici, „high" e de fapt zero risc). **Gap de detecție identificat**: încercarea de a accesa `169.254.169.254` (cloud metadata) **nu e acoperită de nicio regulă custom** — pe un cluster cloud real ar fi un IoC important (T1552.005). **Regulă candidată (Falco — NU implementată)**: `connect` către `169.254.169.254` din container → alertă (relevant pentru extinderea soluției la cloud-managed K8s, menționabil în Cap E „perspective"). **Update 2026-06-18:** gap-ul e ÎNCHIS la nivel **NIDS** — regula custom Suricata sid 1000010 (`K8S-LOCAL Cloud Metadata Service Access Attempt`) prinde tentativa pe rețea (validat la re-rularea de mai sus). Rămâne deschis doar pe latura Falco (runtime), unde un `connect` la 169.254.169.254 încă n-are regulă custom.

4. **Plasarea pe node-4 vs vizibilitatea Falco.** Job-ul rulează pe node-4, dar Falco fiind DaemonSet pe toate nodurile, detecția nu depinde de nod — spre deosebire de Suricata (s09) unde plasarea cross-node față de țintă e esențială pentru vizibilitate. Diferența de model (host-based runtime vs network-based IDS) e ilustrată direct de contrastul s10 ↔ s09.

## False negatives potențiale

- **kube-hunter în mod remote/network (`--remote`/`--cidr`)** în loc de `--pod` — ar scana din afara perimetrului pod-ului; detecția ar depinde de unde rulează scanner-ul. Modul `--pod` (insider) e cel mai relevant pentru threat model-ul „pod compromis".
- **Scanner K8s care nu atinge filesystem-ul de secrete** (doar API enumeration cu un token deja exfiltrat) — ar fi prins doar de `Contact K8S API Server`, nu și de regulile pe citirea fișierelor. Vezi s11 pentru varianta „token folosit fără re-citire".
- **Cloud metadata access real** — neacoperit (vezi obs. #3), gap documentat.
