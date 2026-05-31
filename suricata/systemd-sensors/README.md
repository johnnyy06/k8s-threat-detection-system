# Suricata systemd sensors — extindere NIDS la node-3 (calea aleasă)

Extinde stratul NIDS de pe node-2 (systemd) cu un sensor pe **node-3** — rezolvă limitarea de captură single-node din s09 (un sensor pe node-2 vede doar traficul node-2). Varianta cloud-native (Suricata ca DaemonSet, ca Falco) a fost evaluată dar nu aleasă (vezi „De ce systemd") — rămâne direcție de optimizare (Cap E).

## Arhitectura finală a sensorilor (decisă 2026-05-31)

| Nod | Sensor Suricata | De ce |
|---|---|---|
| node-2 | ✅ systemd (existent) | nodul „security"; vede traficul pod de pe node-2 |
| **node-3** | ✅ **systemd (nou, validat)** | nodul de **aplicații (DVWA/Juice Shop)** = țintele principale de atac. Senzorul stă lângă ȚINTĂ ⇒ prinde atacurile asupra workload-urilor **indiferent de nodul atacatorului** |
| node-4 | ❌ **NU** (deliberat) | nodul **ELK**. Vezi „De ce NU pe node-4" |
| node-1 | ❌ NU | control-plane / dqlite (disk I/O bottleneck). Doar Falco |

**Acoperire:** un atac asupra unui workload de pe node-3 ajunge pe `ens3`-ul node-3 (decapsulat din VXLAN) ⇒ prins de senzorul node-3, **chiar dacă atacatorul e pe alt nod**. Validat: ZAP pe node-4 → DVWA node-3 ⇒ **21 alerte ET WEB_SERVER atribuite senzorului node-3** (înainte, cu sensor doar pe node-2: 0). node-4 și node-1 sunt acoperite la nivel runtime de Falco (DaemonSet pe toate nodurile).

## De ce NU pe node-4 (nodul ELK)

Opinia din domeniu: **nu co-loca un IDS de rețea cu log store-ul (ELK)** — acceptabil doar pentru all-in-one mic (ex. SELKS), nu în „producție". Motive concrete aici:
- **Contention de resurse pe toate cele 3 axe** (CPU/RAM/disk-IO): Suricata (workers, 66k reguli, hyperscan) + ES (heap mare, disk-IO la indexare/merge) + Logstash (procesează TOATĂ telemetria clusterului) + `eve.json` (24GB pe node-2!) s-ar bate pe aceleași resurse — **risc direct asupra pipeline-ului care ingerează toate detecțiile**, pe un cluster cu disk I/O bottleneck cunoscut.
- **Single point of failure**: un spike/atac volumetric care îneacă nodul ar pierde **simultan** detecția ȘI log store-ul.
- **Semnal-zgomot prost**: pe `ens3`-ul node-4 converge tot traficul de monitoring (Falco×4 → Logstash, beats, query-uri ES) ⇒ ai „monitoriza propria instalație de logging".
- **Acoperire deja asigurată**: senzorul node-3 prinde atacurile asupra workload-urilor; atacurile asupra serviciilor ELK de pe alt nod ies oricum pe `ens3`-ul nodului-sursă. node-4 e high-value target, dar protecția corectă = **Falco (runtime, deja prezent) + access control / NetworkPolicy pe ES:9200/Kibana:5601/Logstash:5044**, NU un sniffer co-locat care îi mărește suprafața de atac.

> Dacă în viitor vrei vizibilitate de rețea pe atacurile direct asupra ELK, varianta corectă e un sensor pe **alt** nod sau un SPAN/mirror port — nu pe node-4.

## De ce systemd (nu DaemonSet)
Consistent cu node-2, low-risk pe un cluster fix cu disk I/O bottleneck (fără pull de imagini ~1GB + bootstrap reguli per-pod), config portabil (`ens3` identic pe toate nodurile ⇒ `suricata.yaml` de pe node-2 merge ca atare). Decizie luată 2026-05-31.

## Setup-ul de replicat (de pe node-2, verificat 2026-05-31)
- Suricata `1:8.0.3-0ubuntu1` (pachet Ubuntu), systemd unit stock: `ExecStart=/usr/bin/suricata --af-packet -c /etc/suricata/suricata.yaml ...` (interfața din config).
- `af-packet: interface: ens3`; `HOME_NET` include pod CIDR + svc CIDR; `EXTERNAL_NET: any`.
- Reguli: ET Open via `suricata-update` → `/var/lib/suricata/rules/suricata.rules` (~63.8k reguli).
- Shipping: Filebeat `8.19.10`, citește `/var/log/suricata/eve.json` → `output.logstash: 10.11.0.3:5044`.

## Runbook

### Pas 0 — (de pe laptop) copiază configurile known-good de pe node-2
Acces prin cheie + IP flotant (ex. `node-2 = 10.102.10.54`, `node-3 = <IP_node3>`). Adaptează la mediul tău.
```bash
KEY=licenta-key.pem; N2=10.102.10.54; N3=<IP_flotant_node-3>
# stage configurile (root-owned) in home-ul ubuntu de pe node-2, apoi trage-le pe laptop
ssh -i "$KEY" ubuntu@$N2 'sudo cp /etc/suricata/suricata.yaml /etc/filebeat/filebeat.yml ~/ && sudo chown ubuntu ~/suricata.yaml ~/filebeat.yml'
scp -i "$KEY" ubuntu@$N2:~/suricata.yaml /tmp/suricata.yaml
scp -i "$KEY" ubuntu@$N2:~/filebeat.yml  /tmp/filebeat.yml
ssh -i "$KEY" ubuntu@$N2 'rm -f ~/suricata.yaml ~/filebeat.yml'
# urca-le pe node-3
scp -i "$KEY" /tmp/suricata.yaml /tmp/filebeat.yml ubuntu@$N3:~/
```

### Pas 1 — pe node-3: install + config + reguli + start
```bash
# 1) Suricata 8.0.x din PPA-ul OISF (ca node-2; PPA da 8.0.5, node-2 are 8.0.3 - ambele 8.x OK).
#    ATENTIE: arhiva Ubuntu jammy
#    livreaza doar Suricata 6.0.4 - PREA VECHI, incompatibil cu config-ul 8.x de
#    pe node-2 (esueaza la "request-body-limit - 100 KiB"). PPA-ul e obligatoriu.
sudo apt-get install -y software-properties-common
sudo add-apt-repository -y ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install -y suricata
suricata -V                          # confirma 8.0.x (NU 6.0.4)
# NOTA troubleshooting: daca ai instalat din greseala intai suricata 6.0.4 (din
# arhiva Ubuntu) inainte de PPA, upgrade-ul la 8.0.5 esueaza cu conflict de fisier
# pe /usr/bin/suricata-update (pachetul standalone suricata-update 1.2.3 vs cel
# bundle-uit in 8.0.5). Fix: `sudo apt-get remove -y suricata-update && sudo apt-get install -y suricata`.
# Adaugand PPA-ul INAINTE de primul install (ca aici) eviti complet conflictul.

# 2) Filebeat 8.x (repo Elastic). Daca repo-ul e deja prezent, sari peste add.
if [ ! -f /etc/apt/sources.list.d/elastic-8.x.list ]; then
  wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/elastic-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
  sudo apt-get update
fi
sudo apt-get install -y filebeat

# 3) Pune configurile known-good de pe node-2 (ens3 e identic => merg ca atare)
sudo install -o root -g root -m 0640 ~/suricata.yaml /etc/suricata/suricata.yaml
sudo install -o root -g root -m 0600 ~/filebeat.yml  /etc/filebeat/filebeat.yml
rm -f ~/suricata.yaml ~/filebeat.yml
# IMPORTANT: filebeat.yml de pe node-2 are `node: node-2` hardcodat (fields_under_root).
# Patch-uieste eticheta per-nod ca evenimentele sa fie atribuite corectului sensor:
sudo sed -i 's/node: node-2/node: '"$(hostname)"'/' /etc/filebeat/filebeat.yml
grep 'node:' /etc/filebeat/filebeat.yml

# 4) Reguli ET Open (aceeasi sursa ca node-2)
sudo suricata-update
sudo suricata -T -c /etc/suricata/suricata.yaml      # test config (trebuie "successfully loaded")

# 5) Logrotate pentru eve.json (pe node-2 e 24GB! protejam discul)
sudo tee /etc/logrotate.d/suricata-eve >/dev/null <<'EOF'
/var/log/suricata/eve.json {
    daily
    rotate 3
    size 500M
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        /bin/kill -HUP $(cat /run/suricata.pid 2>/dev/null) 2>/dev/null || true
    endscript
}
EOF

# 6) Enable + restart (restart, NU doar enable --now: pachetul a pornit deja
#    serviciile cu configul default la install; restart incarca configul nostru)
sudo systemctl enable suricata filebeat
sudo systemctl restart suricata; sleep 8
sudo systemctl restart filebeat; sleep 4
sudo systemctl is-active suricata filebeat
sudo suricatasc -c 'iface-stat ens3' 2>/dev/null
sudo tail -5 /var/log/suricata/suricata.log 2>/dev/null
```

### Pas 2 — verificare per nod
```bash
# Suricata capteaza pe ens3? (pkts > 0, drop mic)
sudo suricatasc -c 'iface-stat ens3' 2>/dev/null
# eve.json creste?
sudo ls -la /var/log/suricata/eve.json
# filebeat trimite spre logstash fara erori?
sudo journalctl -u filebeat -n 20 --no-pager | grep -iE 'error|established|connection' | tail
```

## Validare end-to-end (DOVADĂ, rulat 2026-05-31)
Re-rulat s09 cu ZAP pe **node-4** (atacator remote) → DVWA node-3. Scopul: senzorul **node-3** (lângă țintă) prinde atacul deși atacatorul e pe alt nod.
```bash
# zap-scan-job.yaml are nodeSelector -> node-4; apoi:
cd attack-scenarios/09-owasp-zap && ./attack.sh
# verificare per-sensor in ES (campul top-level `node`):
curl -s "$ES_URL/security-*/_search?size=0" -H 'Content-Type: application/json' -d '{"query":{"bool":{"must":[
  {"term":{"tags":"suricata"}},{"term":{"event_type.keyword":"alert"}},
  {"query_string":{"query":"rule.name:*WEB_SERVER*"}},{"range":{"@timestamp":{"gte":"now-15m"}}}]}},
  "aggs":{"by_node":{"terms":{"field":"node.keyword"}}}}'
```
**Rezultat:** **21 alerte ET WEB_SERVER** (SQLi UNION SELECT, PHP RFI, allow_url_include, auto_prepend, PHP.//Input, .htaccess), **toate atribuite senzorului `node-3`** (21/21, 0 de pe node-2). Înainte (sensor doar pe node-2): ZAP pe node-4 → 0 alerte. ⇒ **gap-ul de topologie e închis; node-4 NU e necesar.**

> Nuanță: numărul de semnături ET pe această rulare (~21) e mai mic decât cel cu ZAP pe node-2 (~208) — probabil din cauza reasamblării fluxurilor HTTP peste VXLAN (`cluster_flow` poate hash-ui pe header-ele VXLAN exterioare). Varietatea de tipuri de atac prinse e însă aceeași; pentru validarea acoperirii e suficient. De investigat eventual `cluster-type` / decode VXLAN dacă vrei paritate de count.

## Note / limitări
- **node-2 rămâne neatins** (systemd, validat). Acoperire finală: node-2 + node-3 au sensori; node-1 + node-4 doar pe Falco (vezi „De ce NU pe node-4").
- **eve.json 24GB pe node-2** — pune și acolo logrotate-ul de mai sus (separat) ca să nu umpli discul; e o problemă latentă.
- **Trafic intra-node pod-to-pod** poate să nu atingă `ens3` (rămâne pe veth `cali*`) → sniffing-ul pe ens3 îl poate rata; scenariile noastre sunt cross-node deci ok.
- **Atribuire per-sensor**: câmpul top-level `node` (din `filebeat.yml`, patch-uit per host) = sensorul care a capturat. Filebeat 8.19.16 instalat pe node-3 (node-2 are 8.19.10 — ambele 8.x, OK).
