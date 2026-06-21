# Scenariul 11 — Lateral Movement

**MITRE ATT&CK:** T1552.001 (Unsecured Credentials: Container API / SA token) → T1550.001 (Use Alternate Authentication Material: Application Access Token), T1613 (Container and Resource Discovery), T1021 (Remote Services — pod-to-pod east-west). Tactică: **TA0008 Lateral Movement** (singurul scenariu care o acoperă explicit).

## Idee

Un atacator care a compromis deja `attack-pod` (vezi s03/s06) trece la faza de *lateral movement*: fură token-ul ServiceAccount montat în pod și îl folosește ca să se autentifice la K8s API server, încearcă să pivoteze către alte namespace-uri (enumerare secrete în `kube-system`), verifică ce permisiuni are token-ul (privilege discovery), apoi se mișcă east-west către un alt pod (DVWA). Folosește doar `attack-pod` existent + `curl` + `nc` + token-ul SA deja montat — **fără image pull, fără pod nou**.

Scenariul e *showcase-ul deliberat* al regulii default `Contact K8S API Server From Container`, care până acum apăruse doar accidental (în s02 am evitat intenționat IP-ul API ca să nu o declanșăm).

## Pași de atac

1. **Furt token SA** — `cat /var/run/secrets/kubernetes.io/serviceaccount/token` în pod. Credentialul de pivot. [T1552.001]
2. **Autentificare la K8s API cu token-ul furat** — `curl -k -H "Authorization: Bearer $TOKEN" https://$KUBERNETES_SERVICE_HOST:443/api/v1/namespaces/attack-target/pods`. [T1550.001]
3. **Pivot cross-namespace** — `GET /api/v1/namespaces`, `GET /api/v1/namespaces/kube-system/secrets`, `GET /api/v1/secrets`. Enumerare laterală spre alte namespace-uri. [T1550.001 / T1613 / T1069]
4. **Privilege discovery** — `POST /apis/authorization.k8s.io/v1/selfsubjectaccessreviews` (pot lista secrete în `kube-system`?). Recon clasic înainte de mișcarea reală. [T1613]
5. **East-west move (pod-to-pod)** — `curl http://10.1.139.66/` (DVWA index) + `nc -zv 3306/80/8080` (probe MySQL DVWA). Trafic cross-node node-4→node-3 → vizibil pentru Suricata. [T1021]

## Reguli relevante

| Regulă | Tip | Priority | Match pe |
|---|---|---|---|
| `Contact K8S API Server From Container` | default | Notice | conexiune TCP către IP-ul API server (`10.152.183.1:443`) dintr-un container ne-exceptat — pașii 2, 3, 4 ★ |
| `K8S_THREAT: Kubernetes Secret Access from Pod` | custom | Notice | `cat` citește `.../serviceaccount/token` — pașii 1–4 |
| `K8S_THREAT: Sensitive File Read in Container` | custom | Warning | citire `.../serviceaccount/namespace` (alt fișier din mount-ul de secrete) — pasul 1 |
| `K8S_THREAT: Network Scanning Tool in Container` | custom | Warning | `nc` port-probe — pasul 5 (overlap s05) |
| `K8S_THREAT: Data Exfiltration - Transfer Tool in Container` | custom | Warning | `curl`/`nc` în lista `data_exfil_tools` — pașii 2-5 (overlap s07) |
| `Drop and execute new binary in container` | default | Critical | `curl`/`nc` nu fac parte din base image-ul `ubuntu:22.04` — fiecare exec |

## Rezultate finale (helm rev 26, rulare 2026-05-30)

### Falco — 31 detecții pe `attack-pod`, toate true positive

| Regulă | Tip | Priority | Count | Generată de |
|---|---|---|---|---|
| `Drop and execute new binary in container` | default | Critical | 9 | 6× `curl` + 3× `nc` (binare ne-prezente în base image) |
| `K8S_THREAT: Data Exfiltration - Transfer Tool in Container` | custom | Warning | 9 | 6× `curl` + 3× `nc` (overlap s07) |
| **`Contact K8S API Server From Container`** | **default** | **Notice** | **5** | **5 conexiuni API: pas 2 (×1), pas 3 (×3), pas 4 (×1)** ★ |
| `K8S_THREAT: Kubernetes Secret Access from Pod` | custom | Notice | 4 | 4× `cat .../serviceaccount/token` (pașii 1-4) |
| `K8S_THREAT: Network Scanning Tool in Container` | custom | Warning | 3 | 3× `nc -zv` port-probe (pasul 5, overlap s05) |
| `K8S_THREAT: Sensitive File Read in Container` | custom | Warning | 1 | `cat .../serviceaccount/namespace` (pasul 1) |
| **Total** | | | **31** | |

> Notă de atribuire: interogarea brută `tags:falco` în fereastra de timp întoarce **53** evenimente — diferența de 22 e **zgomot de background din alte pod-uri** (vezi observația #3), filtrat aici cu `kubernetes.pod.name = attack-pod`. Documentul raportează doar detecțiile generate de atacul nostru.

### Răspunsuri API (confirmă modelul de detecție „intent vs success")

| Pas | Request | HTTP | Interpretare |
|---|---|---|---|
| 2 | `GET /api/v1/namespaces/attack-target/pods` | **403** | SA `default` n-are RBAC; **dar conexiunea e detectată** |
| 3 | `GET /api/v1/namespaces` | **403** | pivot blocat de RBAC, detectat |
| 3 | `GET /api/v1/namespaces/kube-system/secrets` | **403** | exfil secrete blocat, detectat |
| 4 | `POST selfsubjectaccessreviews` | **201** | orice user autentificat își poate face self-review → recon reușit |
| 5 | `GET http://10.1.139.66/` (DVWA) | **302** | pod-ul e accesibil east-west (redirect login.php) |
| 5 | `nc 10.1.139.66:80` | **open** | DVWA HTTP up; `:3306`/`:8080` refused (MySQL nu e expus în pod) |

**Detection rate:** 5/5 pași generează alertă (100%). Pasul cel mai important — pasul 2/3/4 (folosirea token-ului la API) — e prins de `Contact K8S API Server` chiar dacă RBAC respinge request-urile.
**False positive rate (atribuit attack-pod):** 0.

### Suricata
**0 alerte de signature** pe mișcarea east-west (pasul 5), din motive cumulate: (a) conexiunea către API server (pașii 2-4) e TLS criptat (HTTPS:443) → Suricata ar vedea doar handshake-ul, nu conținutul; traficul HTTP banal pod-to-pod + port-probe `nc` nu declanșează semnături ET; și (b) **attack-pod rulează pe node-4, iar sensorul Suricata e pe node-2** (vezi s09 obs. #2) → traficul nici n-ar fi capturat. **Detecția lateral movement-ului prin K8s API e exclusiv treaba Falco** (runtime, vede syscall-ul `connect` + procesul + token-ul), nu a NIDS-ului — concluzie validă indiferent de plasare. Demarcație importantă pentru Cap D.

## Re-validare pe helm rev 30 (2026-06-18) — attack-pod pe node-2: Suricata prinde acum east-west

Re-rulat cu attack-pod pe **node-2** (nu node-4 ca în textul de mai jos, acum istoric). Două schimbări:

- **Falco: 31 evenimente — identic cu baseline-ul rev 26** (Drop&execute ×9, Data Exfil ×9, Contact K8S
  API ×5, Secret Access ×4, Network Scanning ×3, Sensitive File Read ×1). API responses identice
  (403/403/403/403/201/302). **NOU: query-ul brut `tags:falco` pe fereastra de timp întoarce acum 31**
  (era 53 în baseline, diferența fiind zgomotul `prometheus`) — **FP-ul de background din obs. #3 e
  confirmat dispărut** (fix-ul helm rev 27/28 ține; nu mai e nevoie de filtrare pe `kubernetes.pod.name`
  în această fereastră). Detecția centrală (`Contact K8S API Server` ×5 pe pivot-ul API) intactă.
- **Suricata — SCHIMBARE: pasul 5 (east-west) e ACUM detectat prin signature** (era „0 alerte"):
  - `ET SCAN Suspicious inbound to mySQL port 3306` ×2 — probe-ul `nc 10.1.139.66:3306` (MySQL DVWA).
  - `ET HUNTING curl User-Agent to Dotted Quad` ×1 — `curl http://10.1.139.66/` (curl UA spre IP direct,
    pattern de tool într-un workload).
  - Plus anomalii (STREAM invalid timestamp ×3, HTTP excessive header ×1).

  Cauza: attack-pod pe **node-2** (nod cu senzor) + pasul 5 e **inter-nod** spre DVWA pe node-3 → prins
  de senzorul node-3 (sensor-near-target). Vechiul text „attack-pod pe node-4 → Suricata-blind" e **depășit**.
  **Pașii 2-4 (API) rămân ascunși de TLS** (HTTPS:443) — niciun signature, ca înainte. Deci s11 a devenit
  **cross-tool autentic**: Falco prinde pivot-ul prin API (TLS-opac pentru NIDS), Suricata prinde mișcarea
  east-west pod-to-pod (HTTP/port-probe în clar). Cele două straturi acoperă faze diferite ale lateral
  movement-ului — exact teza de defense-in-depth.

1. **`Contact K8S API Server From Container` — showcase-ul lateral movement-ului prin API.** Regula default prinde conexiunea TCP către IP-ul service-ului `kubernetes` (`10.152.183.1:443`) din orice container ne-exceptat. Excepțiile noastre (calico-node, speaker, coredns, metrics-server, …) acoperă componentele de infra legitime; `attack-pod` nu e exceptat → cele 5 conexiuni sunt prinse. **Aceasta este detecția centrală a scenariului**: chiar dacă atacatorul are doar un token cu RBAC minim, **simplul act de a contacta API server-ul dintr-un workload de aplicație e un semnal de alarmă**. Convertește „FP-ul evitat" din s02 într-un TP intenționat.

2. **Modelul „intent vs success" la nivel de RBAC.** Toate request-urile cross-namespace au întors **403** (SA `default` din `attack-target` n-are voie să listeze secrete în `kube-system`). Falco detectează **încercarea** (conexiunea + procesul), nu rezultatul HTTP — exact ca în s03 unde `nc -e` era detectat deși flag-ul era respins de OpenBSD nc. Pentru un SOC, un val de 403-uri de la API server originat dintr-un pod de aplicație e *în sine* un IoC puternic (token furat folosit pentru recon). RBAC e linia 2 de apărare (prevenție); Falco e detecția care arată că cineva *testează* linia aia.

3. **FP de background descoperit ȘI REPARAT (helm rev 27, 2026-06-13) — `prometheus` citește propriul token SA.** Interogarea cluster-wide a arătat 22 de evenimente suplimentare de la pod-ul `prometheus` (namespace `observability`) care declanșau `K8S_THREAT: Kubernetes Secret Access from Pod` + `Sensitive File Read` citindu-și **propriul** `serviceaccount/token` și `ca.crt` în mod legitim. Era un **fals pozitiv real** al regulii custom: lista `not proc.name in (...)` nu includea componentele de observability. **Fix aplicat:** listă nouă `allowed_sa_readers: [prometheus, kube-state-metr, grafana, hostpath-provis]` + `not proc.name in (allowed_sa_readers)` adăugat la **ambele** reguli (`Kubernetes Secret Access from Pod` și `Sensitive File Read in Container`). `node_exporter` NU a fost necesar (nu citește token-ul); numele generice `python`/`operator`/`promtail` au fost excluse deliberat — aparțineau stack-ului `kube-prom-stack` abandonat (pod-uri inexistente, doar evenimente istorice). Validare: agregarea ES pe `output_fields.proc.name.keyword` a arătat că FP-urile erau un **burst de churn 2026-05-17..22** (~140k/zi, `prometheus` blocat într-un loop de reconectare la API care își re-citea token-ul), liniștit de atunci → fix-ul e **preventiv** (întărește regula împotriva următorului restart/rotație de token). Un test pozitiv post-deploy (`cat` token/ca.crt/shadow din `attack-pod`) a confirmat că detecția reală rămâne intactă. Material direct pentru subcapitolul „limitări și tuning continuu" din Cap D — într-un cluster shared, regulile pe citirea token-ului SA au nevoie de un allowlist pe componentele de observability, scopat pe nume de proces (nu pe namespace) ca să rămână chirurgical. **Follow-up (rev 28):** testul negativ (repornirea pod-ului `kube-state-metrics` pentru a forța re-citirea token-ului) a scos la iveală un al treilea FP din aceeași familie — regula default `Contact K8S API Server From Container` (cea pe care acest scenariu o pune în valoare, fired ×5 pe `attack-pod`) se declanșa și pe `kube-state-metrics`/`prometheus` care contactează legitim API-ul. Rezolvat prin adăugarea unei excepții `observability_stack` (`[kube-state-metr, /kube-state-metrics]`, `[prometheus, /bin/prometheus]`) la blocul `override: exceptions: append` al regulii. Validat live: restart KSM = 1 eveniment sub rev 27 → 0 sub rev 28 (pod-ul a ajuns 1/1 Ready, deci CHIAR a contactat API-ul → excepția funcționează). Lecție pentru Cap D: un test negativ bun (forțarea acțiunii benigne) descoperă FP-uri adiacente pe care interogarea pasivă nu le arată în regim stabil.

4. **Conexiunea TLS la API ascunde payload-ul de Suricata.** Tot traficul cu API server-ul e HTTPS (443) → Suricata vede doar `tls` handshake (SNI = `10.152.183.1`/`kubernetes.default`), nu și verb-ul/path-ul/token-ul. Aceasta justifică de ce **runtime security (Falco) e indispensabil pentru detecția lateral movement-ului K8s-native** — un NIDS pe trafic criptat nu poate distinge un `GET /pods` legitim de o exfiltrare de secrete. Cele două straturi sunt complementare, nu redundante.

## False negatives potențiale

- **Token folosit din afara clusterului** — dacă atacatorul exfiltrează token-ul și îl folosește de pe laptopul lui (nu din pod), `Contact K8S API Server From Container` (regulă pe container) nu se aplică; detecția ar trebui să vină din K8s audit log (`k8saudit` plugin — neactivat) sau din anomalii de IP sursă la nivel API server. Demarcație de perimetru, ca în s08.
- **Lateral movement fără API** — mișcare pur pod-to-pod (ex. exploit direct pe un serviciu intern vulnerabil, fără să atingă API server-ul) ar fi prinsă doar parțial (Network Scanning pe `nc`/`nmap`, dar nu și exploit-ul aplicativ în sine — acela e domeniul Suricata/WAF, vezi s09).
- **Token cu RBAC larg (SA supra-privilegiat)** — dacă SA-ul ar fi avut drepturi reale, request-urile ar fi întors 200 și atacatorul ar fi extras secretele; detecția Falco e identică (tot pe conexiune), dar impactul ar fi fost real. Întărește argumentul pentru least-privilege RBAC + `automountServiceAccountToken: false` pe pod-urile care nu au nevoie.
