# Scenarii de atac - rezumat detectii

Cele 11 scenarii de atac pentru validarea pipeline-ului de detectie (Falco syscall + Suricata NIDS + k8saudit admission + Falco Talon raspuns automat + ML/IDS second opinion). Fiecare folder are `attack.sh` (executa atacul + interogheaza Elasticsearch pentru ce a declansat) si `expected-detections.md` (detalii + istoric tuning).

Cifrele de mai jos sunt din re-run-ul complet **2026-07-13** (Falco helm rev 30, k8saudit activ, Talon activ, ML activ).

## Pipeline de ingestie si corelare (cum ajung alertele in ES)

```
Falco (syscall, toate nodurile) ─┐
Falco k8saudit (admission) ──────┼─> falcosidekick ─> Webhook :5045 (HTTP) ─┐
                                 └────────────────────> Talon :2803 (raspuns)│
Suricata (node-2,3) ─> eve.json ─> Filebeat ─> :5044 (Beats) ───────────────┴─> Logstash ─> ES  security-YYYY.MM.dd
```

Logstash (`elk/logstash/logstash-security.conf`, systemd pe node-4) primeste pe **:5045** (Falco via falcosidekick HTTP) si **:5044** (Suricata via Filebeat Beats), apoi normalizeaza ambele surse pe acelasi schelet **ECS** (aditiv - campurile brute raman) in **4 stage-uri**:
- **Stage 1 - tagging:** `tags: falco` / `tags: suricata`.
- **Stage 2 - ECS:** motoare diferite -> campuri canonice comune. Falco `rule`->`rule.name`, `priority`->`event.severity`, `source`->`event.provider` (syscall|k8s_audit), `output_fields[k8s.pod.name]`->`kubernetes.pod.name`. Suricata `alert.signature`->`rule.name`, `alert.signature_id`->`rule.id`, `src_ip/dest_ip`->`source.ip/destination.ip`.
- **Stage 3 - MITRE:** tag-urile `T####` ale regulilor Falco -> `threat.technique.*` + `threat.tactic.*`.
- **Stage 4 - auto-tag scenarii:** poduri fara reguli custom (zap-scan-*, kube-hunter-*, escape-pod, malicious-pod, curl cu Bearer) primesc `scenario_NN`.

**Output:** toate intr-un singur index zilnic `security-YYYY.MM.dd`. Agregarea (index unificat) + normalizarea la schema comuna sunt ce fac posibila **corelarea cross-tool** pe campuri partajate: `kubernetes.pod.name` (Falco syscall <-> k8saudit admission), `destination.ip` (Falco <-> Suricata), `flow_id` (Suricata determinist <-> ML). ML (`security-ml-*`) si Talon (`falco-talon-*`) scriu in indici separati: ML citeste `security-*` si adauga a doua opinie; Talon primeste direct de la falcosidekick (nu prin Logstash).

## Prerechizite (o singura data, inainte de rulare)

```bash
# 1. .env la radacina repo-ului trebuie sa contina endpoint-ul ES (floating IP node-4):
#    ES_URL=http://10.102.14.31:9200
cat ../.env | grep ES_URL

# 2. attack-pod trebuie sa ruleze si sa aiba uneltele instalate (se pierd la restart pod):
kubectl get pod attack-pod -n attack-target
kubectl exec -n attack-target attack-pod -- bash -c \
  'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && \
   apt-get install -y -qq nmap netcat-openbsd curl wget dnsutils tar iproute2'

# 3. IP-uri efemere (se schimba la recreare pod) - verifica si actualizeaza in scripturi daca difera:
kubectl get pod dvwa -n vulnerable-apps -o jsonpath='{.items..status.podIP}' 2>/dev/null; \
kubectl get pods -n vulnerable-apps -o wide | grep dvwa   # tinta web (s05/s09/s11)
kubectl get pod attack-pod -n attack-target -o jsonpath='{.status.podIP}'   # atacatorul
# La ultimul run: DVWA=10.1.139.106, attack-pod=10.1.247.9, falco node-3=10.1.139.103
```

## IMPORTANT: cleanup Talon dupa s03 si s02

Scenariile **03** (reverse shell) si **02** (crypto mining, prin misatribuirea pattern-ului `/dev/tcp`) declanseaza regula Talon de reverse shell, care **izoleaza attack-pod** (NetworkPolicy + label `compromised=true`). Daca nu revii, scenariile urmatoare raman blocate la retea. Ruleaza dupa fiecare din cele doua:

```bash
kubectl delete networkpolicy attack-pod -n attack-target
kubectl label pod attack-pod -n attack-target compromised-
```

## Ordine recomandata de rulare

`04 -> 06 -> 05 -> 03 -> 07 -> 02 -> 01 -> 08 -> 09 -> 10 -> 11`
(cele syscall/rapide intai; s09 ZAP e cel mai lung ~8-10 min; s09 are nevoie de imaginea ZAP ~1.3GB pre-pull pe node-2.)

---

## Rezumat per scenariu

### 04 - Sensitive File / Secret Access (T1552)
```bash
cd 04-sensitive-file && ./attack.sh
```
Citeste `/etc/shadow`, `/etc/gshadow`, si token-ul ServiceAccount montat.
**Detectii (6, Falco):** Sensitive File Read ×4, Kubernetes Secret Access ×1, Read sensitive file untrusted ×1. 0 FP, 100% acoperire.
**Talon:** nu. **ML:** N/A (fara trafic de retea - pur syscall).

### 06 - Privilege Escalation (T1548)
```bash
cd 06-privilege-escalation && ./attack.sh
```
Seteaza biti setuid/setgid, ruleaza `su` si `sudo`, instaleaza pachete.
**Detectii (~10, Falco):** Privilege Escalation Setuid/Setgid ×3, Drop&execute ×2, Package Manager ×2, Sudo/Su ×2. **1 FP cunoscut:** FIM `ldconfig -> /etc/ld.so.cache~` (ldconfig lipseste din allowlist-ul `package_mgmt_binaries`).
**Talon:** nu. **ML:** N/A (syscall).

### 05 - Network Scanning (T1046) - CROSS-TOOL
```bash
cd 05-network-scanning && ./attack.sh
```
`nmap` (TCP connect + SYN + version) pe API/DVWA + `nc` port scan.
**Detectii Falco:** Network Scanning Tool ×6, Drop&execute ×6, Packet socket created ×5, Data Exfil Tool ×3.
**Detectii Suricata:** ET SCAN Nmap Scripting Engine UA ×6, ET SCAN Suspicious mySQL 3306 ×2 + anomalii STREAM. (Query brut include ~2000 "Contact K8S API" = zgomot background cluster, filtreaza pe `kubernetes.pod.name=attack-pod`.)
**Talon:** nu. **ML:** DA - fluxurile scanului sunt scorate ATTACK; scanul catre API (`10.152.183.1`) si DVWA domina bucket-ul ATTACK. Aici determinist (Suricata ET SCAN) si ML sunt in acord (`detection=both`) pe fluxurile de scan reale.

### 03 - Reverse Shell (T1059) - declanseaza Talon
```bash
cd 03-reverse-shell && ./attack.sh
# apoi OBLIGATORIU cleanup Talon (vezi sectiunea de mai sus)
```
`nc` listener + `bash /dev/tcp` + named pipe + `nc -e` + FD-redirect.
**Detectii (34, Falco):** Reverse Shell Command Pattern ×9, Drop&execute ×5, Data Exfil ×5, Network Scanning ×5, Redirect STDOUT/STDIN ×4, Netcat Listener ×3, +3. 0 FP.
**Talon:** DA - izoleaza attack-pod (NetworkPolicy) + label `compromised=true`, reversibil. Vizibil in index `falco-talon-*`. **Cleanup obligatoriu dupa.**
**ML:** N/A (trafic loopback 127.0.0.1, Suricata nu vede -> ML nu are flow).

### 07 - Data Exfiltration (T1048) - CROSS-TOOL, ML complementar
```bash
cd 07-data-exfiltration && ./attack.sh
```
Staging `tar.gz` + exfil prin curl/wget POST + `nc` raw TCP + tunelare DNS.
**Detectii Falco:** Data Exfil Transfer Tool ×3 (curl/wget/nc), Drop&execute ×12. Regula `DNS Exfiltration Suspicion` = **0** (enrichment fd UDP nedeterministic pe eBPF modern - limitare documentata).
**Detectii Suricata (acopera golul Falco):** ET WEB_SERVER WebShell `*.tar.gz` in POST body ×5, **custom `K8S-LOCAL DNS Exfiltration long label` sid 1000012 ×5**. Exemplu clar de defense-in-depth: Falco rateaza exfil-ul DNS, Suricata il prinde.
**Talon:** nu. **ML:** DA - fluxurile de exfil (HTTP POST catre httpbin, DNS catre 8.8.8.8) scorate ATTACK.

### 02 - Crypto Mining (T1496) - declanseaza Talon
```bash
cd 02-crypto-mining && ./attack.sh
# apoi OBLIGATORIU cleanup Talon (misatribuire /dev/tcp -> regula reverse shell)
```
Binare benigne redenumite xmrig/cpuminer/minerd + conexiuni la "pool" ports (fara miner real).
**Detectii (18, Falco):** Crypto Mining Binary Detected ×3, Drop&execute ×5, Binary Downloaded ×3, Data Exfil ×2, Reverse Shell Pattern ×2 (misatribuire `/dev/tcp` documentata), +3. Regula `Crypto Mining Pool Connection` = **0** (acelasi enrichment fd nedeterministic ca s07).
**Detectii Suricata:** ET WEB_SERVER bash shell piped to `/dev/tcp` ×3.
**Talon:** DA (indirect, prin pattern-ul `/dev/tcp`) - izoleaza attack-pod. **Cleanup obligatoriu.** (Regula Talon crypto e scoped pe `talon-demo`, deci attack-pod nu e omorat.) Evenimentele Secret Access + Contact K8S API din fereastra sunt activitatea proprie a pod-ului Talon (FP de ordin 2, documentat).
**ML:** partial (fara Stratum real, putin flow de mining).

### 01 - Container Escape (T1611) - 2 STRATURI (syscall + admission)
```bash
cd 01-container-escape && ./attack.sh   # deploy escape-pod pe node-3, ruleaza atacul, sterge pod-ul
```
Deploy pod privilegiat (hostPID, hostNetwork, hostPath `/`, containerd.sock) + `nsenter`/`chroot`/`unshare` breakout.
**Detectii strat syscall (13, Falco):** Container Escape Nsenter/Chroot ×9, Sensitive Mount Access ×2, Sensitive File Read ×1, Read untrusted ×1 (chroot citeste `/etc/shadow` al HOST-ului).
**Detectii strat admission (4, k8saudit) - NOU:** `Create Privileged Pod`, `Create Sensitive Mount Pod`, `Create HostNetwork Pod`, `Create HostPid Pod` (×1 fiecare). **Aici se inchide gap-ul deploy-time** pe care Falco syscall structural nu-l poate vedea. Distins in ES prin `event.provider=k8s_audit`.
**Talon:** nu. **ML:** N/A (syscall/admission).

### 08 - Malicious Deployment (T1610) - 2 STRATURI (syscall + admission)
```bash
cd 08-malicious-deployment && ./attack.sh   # deploy malicious-pod pe node-3, atac, cleanup
```
Deploy pod privilegiat + apt install + download+chmod+exec payload din `/tmp`.
**Detectii strat syscall (Falco):** Binary Downloaded&Executed ×3, Drop&execute ×3, Package Manager ×2, Data Exfil ×1. **1 FP:** FIM `ldconfig -> /etc/ld.so.cache~` (acelasi ca s06).
**Detectii strat admission (3, k8saudit) - NOU:** `Create Privileged Pod`, `Create Sensitive Mount Pod`, `Create HostPid Pod` (fara HostNetwork - malicious-pod nu-l cere).
**Talon:** nu. **ML:** N/A.

### 09 - OWASP ZAP (T1190) - dominat de Suricata, ML complementar
```bash
cd 09-owasp-zap && ./attack.sh   # deploy Job ZAP pe node-2, ~8-10 min, cleanup automat
```
DAST full scan (spider + active scan, payload-uri SQLi/XSS/RFI reale) impotriva DVWA.
**Detectii Suricata (2938 alerte, 826 HIGH):** PHP RFI ×78, `allow_url_include` ×102, `auto_prepend_file` ×98, SQLi exec ×72, SQLi WAITFOR DELAY ×43, XSS script tag ×19, `/etc/passwd` in URI ×11, .htaccess ×13, ... (ruleset ET Open dupa fix-ul HOME_NET). **Cel mai puternic scenariu cross-tool la nivel retea.**
**Detectii Falco:** doar 8 (Drop&execute pe pod-ul scanner ZAP; DVWA neautentificat = login wall, fara exec server-side).
**Raport ZAP:** 0 FAIL / 15 WARN / 126 PASS.
**Talon:** nu. **ML:** DA - fluxurile ZAP->DVWA scorate ATTACK masiv; agreement partial cu Suricata (`detection=both` pe fluxurile web-attack), plus `ml_only` pe fluxuri fara semnatura ET.

### 10 - kube-hunter (T1046/T1552) - dominat de Falco
```bash
cd 10-kube-hunter && ./attack.sh   # deploy Job kube-hunter --pod --active pe node-2, ~1 min, cleanup
```
Recon K8s insider (citeste token SA, creeaza raw sockets, probe metadata).
**Detectii Falco (14, filtrat pe pod):** Sensitive File Read ×7, Packet socket created ×4 (cross-valideaza finding-ul CAP_NET_RAW al kube-hunter), Kubernetes Secret Access ×2, Contact K8S API ×1.
**Detectii Suricata:** custom `K8S-LOCAL Cloud Metadata IMDS 169.254.169.254` sid 1000010 ×1 (gap-ul metadata inchis la nivel NIDS).
**Raport kube-hunter:** 4 vulnerabilitati (KHV050 token SA, CAP_NET_RAW, Access secrets, KHV053 AWS Metadata = FP al uneltei pe on-prem).
**Talon:** nu. **ML:** minim (probe TLS catre API, putine flow-uri cu semnatura).

### 11 - Lateral Movement (TA0008) - showcase Contact K8S API
```bash
cd 11-lateral-movement && ./attack.sh
```
Fura token SA -> pivot API K8s (cross-namespace, toate 403) -> SelfSubjectAccessReview -> east-west pod-to-pod la DVWA.
**Detectii (31, Falco):** Drop&execute ×9, Data Exfil ×9, **Contact K8S API Server ×5** (regula showcase), Kubernetes Secret Access ×4, Network Scanning ×3, Sensitive File Read ×1. 0 FP. "Intent vs success": toate request-urile API sunt 403 dar detectia e pe conexiune.
**Detectii Suricata (east-west):** ET SCAN mySQL 3306 ×2, ET HUNTING curl UA to Dotted Quad ×1.
**Talon:** nu. **ML:** DA - fluxurile catre API (`10.152.183.1`) si east-west catre DVWA scorate ATTACK.

---

## Rezumat global (run 2026-07-13)

- **Toate 11 scenariile detectate**, consistent cu baseline-ul anterior. Straturile de detectie se completeaza: syscall (Falco) prinde executia/accesul la fisiere, NIDS (Suricata) prinde atacurile de retea/web/exfil, admission (k8saudit) prinde deploy-ul de resurse periculoase.
- **Strat admission (k8saudit) validat live** la s01 (4 reguli) si s08 (3 reguli) - inchide gap-ul deploy-time pe care syscall Falco structural nu-l vede.
- **Talon raspuns automat:** 20 actiuni in `falco-talon-*` (Isolate Pod ×10 + Label Compromised ×10) din s03 + s02. Necesita cleanup manual dupa aceste doua scenarii.
- **ML/IDS (second opinion pe fluxuri Suricata), fereastra run:** din ~16.5k fluxuri scorate, **3200 ATTACK / 13266 BENIGN**. Corelat cu regulile deterministe pe `flow_id`: `both`=649 (ML si Suricata de acord), `ml_only`=2551 (ML flag fara semnatura), `rule_only`=70 (Suricata prinde, ML rateaza), `quiet`=13196. ML e relevant la scenariile cu trafic real de retea (05, 07, 09, 11); acopera larg atacurile de retea dar bucket-ul `ml_only` mare include atat catch-uri fara semnatura cat si FP-uri pe traficul de control-plane catre API (limitarea de domeniu documentata in Cap E). N/A la scenariile pur syscall/loopback (01, 02, 03, 04, 06, 08).
- **FP-uri cunoscute, neschimbate:** FIM `ldconfig -> /etc/ld.so.cache~` (s06/s08); reguli fd-enrichment UDP nedeterministe (`DNS Exfiltration`, `Crypto Mining Pool Connection` = 0), acoperite insa de Suricata.
