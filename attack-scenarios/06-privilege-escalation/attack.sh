#!/bin/bash
# Scenariul 6 - Privilege Escalation (T1548)
# Setuid bit manipulation, sudo/su usage, package manager install in running container

set -e

POD=attack-pod
NS=attack-target
ES=http://10.102.14.31:9200

echo "=================================================="
echo "Scenariul 6 - Privilege Escalation"
echo "Start: $(date +%T)"
echo "=================================================="

START_TS=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
echo "[marker] Start UTC: $START_TS"
echo ""

echo "[step 1/6] chmod 4755 /tmp/escalation (setuid via mode numeric)"
kubectl exec -n $NS $POD -- bash -c "touch /tmp/escalation && chmod 4755 /tmp/escalation && ls -la /tmp/escalation"
echo ""

echo "[step 2/6] chmod u+s /tmp/escalation (setuid via mode simbolic)"
kubectl exec -n $NS $POD -- bash -c "chmod u+s /tmp/escalation && ls -la /tmp/escalation"
echo ""

echo "[step 3/6] chmod 6755 /tmp/escalation (setuid + setgid)"
kubectl exec -n $NS $POD -- bash -c "chmod 6755 /tmp/escalation && ls -la /tmp/escalation"
echo ""

echo "[step 4/6] su -c whoami (esueaza fara parola, dar proc spawn declanseaza regula)"
kubectl exec -n $NS $POD -- bash -c "su -c whoami 2>&1 | head -3 || true"
echo ""

echo "[step 5/6] apt-get update && apt-get install -y sudo (poate dura 30-60s)"
kubectl exec -n $NS $POD -- bash -c "apt-get update -qq 2>&1 | tail -2 && apt-get install -y -qq sudo 2>&1 | tail -3"
echo ""

echo "[step 6/6] sudo whoami"
kubectl exec -n $NS $POD -- sudo whoami
echo ""

echo "=================================================="
echo "Atac terminat. Astept 30s pentru propagare ES..."
echo "=================================================="
sleep 30

echo ""
echo "=== Reguli Falco declansate de la $START_TS ==="
curl -s "$ES/security-*/_search?size=0" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"tags.keyword\":\"falco\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$START_TS\"}}}]}},\"aggs\":{\"by_rule\":{\"terms\":{\"field\":\"rule.keyword\",\"size\":15}},\"by_priority\":{\"terms\":{\"field\":\"priority.keyword\",\"size\":10}}}}" \
  | python3 -m json.tool | sed -n '/aggregations/,$p'

echo ""
echo "=== Sample 10 detectii (cronologic) ==="
curl -s "$ES/security-*/_search?size=10" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"tags.keyword\":\"falco\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$START_TS\"}}}]}},\"sort\":[{\"@timestamp\":\"asc\"}],\"_source\":[\"@timestamp\",\"rule\",\"priority\",\"output\"]}" \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
for h in d.get('hits',{}).get('hits',[]):
    s = h['_source']
    print(f\"  {s.get('@timestamp','?')[:19]} [{s.get('priority','?'):8}] {s.get('rule','?')}\")
    out = s.get('output','')
    if out:
        print(f\"    -> {out[:200]}\")
"

echo ""
echo "End: $(date +%T)"
