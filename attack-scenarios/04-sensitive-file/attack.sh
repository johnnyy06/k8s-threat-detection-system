#!/bin/bash
# Scenariul 4 - Sensitive File / Secret Access (T1552)
# Ruleaza atacul si verifica rezultatele in Elasticsearch

set -e

POD=attack-pod
NS=attack-target
source "$(dirname "$0")/../_env.sh"

echo "=================================================="
echo "Scenariul 4 - Sensitive File / Secret Access"
echo "Start: $(date +%T)"
echo "=================================================="

# Marker timestamp pentru filtrare ulterioara in ES
START_TS=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
echo "[marker] Start UTC: $START_TS"
echo ""

echo "[step 1/5] cat /etc/shadow"
kubectl exec -n $NS $POD -- cat /etc/shadow | head -3
echo ""

echo "[step 2/5] cat /etc/gshadow"
kubectl exec -n $NS $POD -- cat /etc/gshadow | head -3
echo ""

echo "[step 3/5] ls /var/run/secrets/kubernetes.io/serviceaccount/"
kubectl exec -n $NS $POD -- ls -la /var/run/secrets/kubernetes.io/serviceaccount/
echo ""

echo "[step 4/5] cat ServiceAccount token (truncat la 80 char)"
kubectl exec -n $NS $POD -- cat /var/run/secrets/kubernetes.io/serviceaccount/token | head -c 80
echo "..."
echo ""

echo "[step 5/5] cat CA cert (primele 2 linii)"
kubectl exec -n $NS $POD -- cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt | head -2
echo ""

echo "=================================================="
echo "Atac terminat. Astept 30s pentru propagare ES..."
echo "=================================================="
sleep 30

echo ""
echo "=== Reguli Falco declansate de la $START_TS ==="
curl -s "$ES/security-*/_search?size=0" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"tags\":\"falco\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$START_TS\"}}}]}},\"aggs\":{\"by_rule\":{\"terms\":{\"field\":\"rule.name\",\"size\":15}},\"by_priority\":{\"terms\":{\"field\":\"log.level\",\"size\":10}}}}" \
  | python3 -m json.tool | sed -n '/aggregations/,$p'

echo ""
echo "=== Sample 5 detectii (primele cronologic) ==="
curl -s "$ES/security-*/_search?size=5" \
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
        print(f\"    -> {out[:180]}\")
"

echo ""
echo "End: $(date +%T)"
