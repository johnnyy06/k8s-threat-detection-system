#!/bin/bash
# Scenariul 5 - Network Scanning (T1046)
# Cross-tool detection real (Falco + Suricata)

set -e

POD=attack-pod
NS=attack-target
source "$(dirname "$0")/../_env.sh"

# Targets verificate la 2026-06-18 (pod IPs sunt efemere — re-verifică după recreare)
K8S_API=10.152.183.1
DVWA=10.1.139.66
FALCO=10.1.139.101   # falco pod pe node-3 (inter-node față de attack-pod/node-2 → vizibil Suricata)

echo "=================================================="
echo "Scenariul 5 - Network Scanning"
echo "Targets: K8S_API=$K8S_API DVWA=$DVWA FALCO=$FALCO"
echo "Start: $(date +%T)"
echo "=================================================="

START_TS=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
echo "[marker] Start UTC: $START_TS"
echo ""

echo "[step 1/5] apt-get install -y nmap (poate dura 30-60s)"
kubectl exec -n $NS $POD -- bash -c "apt-get install -y -qq nmap 2>&1 | tail -3"
echo ""

echo "[step 2/5] nmap -sT -p 1-1000 K8S_API ($K8S_API) - TCP connect scan"
kubectl exec -n $NS $POD -- nmap -sT -p 1-1000 $K8S_API --max-retries 1 --host-timeout 60s 2>&1 | tail -10
echo ""

echo "[step 3/5] nmap -sS -p 22,80,443,8080,3306 DVWA ($DVWA) - SYN scan"
kubectl exec -n $NS $POD -- nmap -sS -p 22,80,443,8080,3306 $DVWA --max-retries 1 --host-timeout 30s 2>&1 | tail -10
echo ""

echo "[step 4/5] nmap -sV -p 80 DVWA ($DVWA) - service version detection"
kubectl exec -n $NS $POD -- nmap -sV -p 80 $DVWA --max-retries 1 --host-timeout 30s 2>&1 | tail -8
echo ""

echo "[step 5/5] nc -zv FALCO ($FALCO) 80 8080 8443 - netcat connect scan"
kubectl exec -n $NS $POD -- bash -c "for port in 80 8080 8443; do nc -zv -w 2 $FALCO \$port 2>&1 | head -1; done"
echo ""

echo "=================================================="
echo "Atac terminat. Astept 45s pentru propagare ES (Suricata batch flush)..."
echo "=================================================="
sleep 45

echo ""
echo "=== Reguli FALCO declansate de la $START_TS ==="
curl -s "$ES/security-*/_search?size=0" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"tags\":\"falco\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$START_TS\"}}}]}},\"aggs\":{\"by_rule\":{\"terms\":{\"field\":\"rule.name\",\"size\":15}},\"by_priority\":{\"terms\":{\"field\":\"log.level\",\"size\":10}}}}" \
  | python3 -m json.tool | sed -n '/aggregations/,$p'

echo ""
echo "=== Alertele SURICATA declansate ==="
curl -s "$ES/security-*/_search?size=0" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"tags\":\"suricata\"}},{\"term\":{\"event_type.keyword\":\"alert\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$START_TS\"}}}]}},\"aggs\":{\"by_signature\":{\"terms\":{\"field\":\"rule.name\",\"size\":20}},\"by_severity\":{\"terms\":{\"field\":\"alert.severity\",\"size\":10}},\"by_dest\":{\"terms\":{\"field\":\"destination.ip\",\"size\":10}}}}" \
  | python3 -m json.tool | sed -n '/aggregations/,$p'

echo ""
echo "=== Total events (orice tag) cumulate de la atacator (10.1.247.59) ==="
echo -n "Falco events: "
curl -s "$ES/security-*/_count" -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"tags\":\"falco\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$START_TS\"}}}]}}}" 2>&1
echo ""
echo -n "Suricata events: "
curl -s "$ES/security-*/_count" -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"tags\":\"suricata\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$START_TS\"}}}]}}}" 2>&1
echo ""

echo ""
echo "End: $(date +%T)"
