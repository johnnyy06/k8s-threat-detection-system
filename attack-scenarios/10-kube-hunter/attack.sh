#!/bin/bash
# Scenariul 10 - kube-hunter (K8s pentest / recon din interiorul clusterului)
# Deploy un Job care ruleaza kube-hunter in mod --pod --active: descopera API server,
# kubelet, sondeaza token-ul SA, scaneaza subnet-ul de pod-uri si testeaza CVE-uri K8s.
# Scenariu dominat de Falco (recon K8s-native la nivel runtime).
#
# MITRE: T1613 (Container & Resource Discovery), T1046 (Network Service Discovery),
#        T1552.001 (SA token), T1550.001 (use of token), TA0007 (Discovery)
#
# kube-hunter image ~180MB (mai mic decat ZAP). Job se auto-curata (ttlSecondsAfterFinished).

set -e

NS=attack-target
JOB=kube-hunter
source "$(dirname "$0")/../_env.sh"
HERE=$(dirname "$0")

echo "=================================================="
echo "Scenariul 10 - kube-hunter (K8s recon insider)"
echo "Start: $(date +%T)"
echo "=================================================="

START_TS=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
echo "[marker] Start UTC: $START_TS"
echo ""

# Curata orice job vechi
kubectl delete job $JOB -n $NS --ignore-not-found --wait=true 2>&1 | sed 's/^/  /' || true

echo "[step 1/2] kubectl apply kube-hunter-job.yaml (--pod --active)"
kubectl apply -f "$HERE/kube-hunter-job.yaml"
echo "  ... astept pornirea pod-ului (image pull poate dura pe disc lent)"
# Asteapta sa apara pod-ul
for i in $(seq 1 60); do
  PODN=$(kubectl get pods -n $NS -l job-name=$JOB -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  [ -n "$PODN" ] && break
  sleep 3
done
echo "  pod: $PODN"
echo ""

echo "[step 2/2] Astept terminarea kube-hunter (max 6 min)..."
kubectl wait --for=condition=complete job/$JOB -n $NS --timeout=360s 2>&1 \
  || echo "  (job inca ruleaza sau a esuat - continui sa colectez ce a generat)"
echo ""

echo "=================================================="
echo "=== RAPORTUL kube-hunter (ce a descoperit insider-ul) ==="
echo "=================================================="
kubectl logs -n $NS job/$JOB 2>&1 | tail -80

echo ""
echo "Astept 40s pentru propagare ES (Falco batch)..."
sleep 40

echo ""
echo "=== Reguli FALCO declansate de kube-hunter (filtrat pe pod) de la $START_TS ==="
curl -s "$ES/security-*/_search?size=0" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"tags\":\"falco\"}},{\"prefix\":{\"kubernetes.pod.name\":\"kube-hunter\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$START_TS\"}}}]}},\"aggs\":{\"by_rule\":{\"terms\":{\"field\":\"rule.name\",\"size\":20}},\"by_priority\":{\"terms\":{\"field\":\"log.level\",\"size\":10}}}}" \
  | python3 -c "
import sys,json
d=json.load(sys.stdin)
tot=d['hits']['total']['value']
print(f'  TOTAL kube-hunter Falco events: {tot}')
agg=d.get('aggregations',{})
for b in agg.get('by_rule',{}).get('buckets',[]):
    print(f\"   {b['doc_count']:>3}  {b['key']}\")
print('  --- priority ---')
for b in agg.get('by_priority',{}).get('buckets',[]):
    print(f\"   {b['doc_count']:>3}  {b['key']}\")
"

echo ""
echo "=== Sample detectii (cronologic) ==="
curl -s "$ES/security-*/_search?size=12" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"tags\":\"falco\"}},{\"prefix\":{\"kubernetes.pod.name\":\"kube-hunter\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$START_TS\"}}}]}},\"sort\":[{\"@timestamp\":\"asc\"}],\"_source\":[\"@timestamp\",\"rule.name\",\"log.level\",\"output\"]}" \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
for h in d.get('hits',{}).get('hits',[]):
    s = h['_source']
    print(f\"  {s.get('@timestamp','?')[:19]} [{s.get('log',{}).get('level','?'):8}] {s.get('rule',{}).get('name','?')}\")
    out = s.get('output','')
    if out:
        print(f\"    -> {out[:190]}\")
"

echo ""
echo "=== Alertele SURICATA (probe-uri API/kubelet/subnet) ==="
curl -s "$ES/security-*/_search?size=0" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"tags\":\"suricata\"}},{\"term\":{\"event_type.keyword\":\"alert\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$START_TS\"}}}]}},\"aggs\":{\"by_signature\":{\"terms\":{\"field\":\"rule.name\",\"size\":20}},\"by_dest\":{\"terms\":{\"field\":\"destination.ip\",\"size\":10}}}}" \
  | python3 -m json.tool | sed -n '/aggregations/,$p'

echo ""
echo "=== Cleanup: kubectl delete job kube-hunter ==="
kubectl delete -f "$HERE/kube-hunter-job.yaml" --wait=false 2>&1

echo ""
echo "End: $(date +%T)"
