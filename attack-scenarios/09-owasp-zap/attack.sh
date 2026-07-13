#!/bin/bash
# Scenariul 9 - OWASP ZAP (DAST scan vs DVWA)
# Deploy un Job care ruleaza zap-full-scan.py (spider + active scan) impotriva
# pod-ului DVWA. Arunca payload-uri reale SQLi/XSS/path-traversal la nivel HTTP.
# Scenariu dominat de Suricata (atac aplicativ web la nivel retea, cross-node).
#
# MITRE: T1190 (Exploit Public-Facing Application), T1046 (Network Service Discovery),
#        T1595.002 (Active Scanning: Vulnerability Scanning)
#
# ZAP image ~1.3GB - PRE-PULL pe node-2 inainte de rulare (vezi README/job).

set -e

NS=attack-target
JOB=zap-scan
source "$(dirname "$0")/../_env.sh"
HERE=$(dirname "$0")

DVWA_POD=10.1.139.106   # tinta (node-3), verificat 2026-07-13

echo "=================================================="
echo "Scenariul 9 - OWASP ZAP DAST scan vs DVWA ($DVWA_POD)"
echo "ZAP ruleaza pe node-2 (worker cu sensor) -> DVWA pe node-3 (prins de sensorul node-3, inter-nod)"
echo "Start: $(date +%T)"
echo "=================================================="

START_TS=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
echo "[marker] Start UTC: $START_TS"
echo ""

# Curata orice job vechi
kubectl delete job $JOB -n $NS --ignore-not-found --wait=true 2>&1 | sed 's/^/  /' || true

echo "[step 1/2] kubectl apply zap-scan-job.yaml (zap-full-scan.py vs DVWA)"
kubectl apply -f "$HERE/zap-scan-job.yaml"
echo "  ... astept pornirea pod-ului"
for i in $(seq 1 60); do
  PODN=$(kubectl get pods -n $NS -l job-name=$JOB -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  [ -n "$PODN" ] && break
  sleep 3
done
echo "  pod: $PODN"
echo ""

echo "[step 2/2] Astept terminarea scanului ZAP (max 18 min)..."
kubectl wait --for=condition=complete job/$JOB -n $NS --timeout=1080s 2>&1 \
  || echo "  (job inca ruleaza / deadline - continui sa colectez ce a generat)"
echo ""

echo "=================================================="
echo "=== RAPORTUL ZAP (sumar vulnerabilitati gasite in DVWA) ==="
echo "=================================================="
# Sumarul ZAP: liniile FAIL/WARN/PASS + tabelul de la final
kubectl logs -n $NS job/$JOB 2>&1 | grep -E 'FAIL-NEW|WARN-NEW|PASS|FAIL:|WARN:|^(FAIL|WARN|PASS|INFO)' | tail -60
echo ""
echo "--- (full log tail) ---"
kubectl logs -n $NS job/$JOB 2>&1 | tail -15

echo ""
echo "Astept 60s pentru propagare ES (Suricata batch flush e mai lent)..."
sleep 60

echo ""
echo "=== Alertele SURICATA declansate de scan de la $START_TS ==="
curl -s "$ES/security-*/_search?size=0" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"tags\":\"suricata\"}},{\"term\":{\"event_type.keyword\":\"alert\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$START_TS\"}}}]}},\"aggs\":{\"by_signature\":{\"terms\":{\"field\":\"rule.name\",\"size\":25}},\"by_severity\":{\"terms\":{\"field\":\"alert.severity\",\"size\":10}},\"by_dest\":{\"terms\":{\"field\":\"destination.ip\",\"size\":10}},\"by_src\":{\"terms\":{\"field\":\"source.ip\",\"size\":10}}}}" \
  | python3 -m json.tool | sed -n '/aggregations/,$p'

echo ""
echo "=== Suricata: telemetrie ne-alerta (flow/http/anomaly) generata de scan ==="
curl -s "$ES/security-*/_search?size=0" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"tags\":\"suricata\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$START_TS\"}}}]}},\"aggs\":{\"by_event_type\":{\"terms\":{\"field\":\"event_type.keyword\",\"size\":15}}}}" \
  | python3 -m json.tool | sed -n '/aggregations/,$p'

echo ""
echo "=== Reguli FALCO (DVWA exec server-side? de obicei putin) ==="
curl -s "$ES/security-*/_search?size=0" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"tags\":\"falco\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$START_TS\"}}}]}},\"aggs\":{\"by_rule\":{\"terms\":{\"field\":\"rule.name\",\"size\":15}},\"by_pod\":{\"terms\":{\"field\":\"kubernetes.pod.name\",\"size\":15}}}}" \
  | python3 -m json.tool | sed -n '/aggregations/,$p'

echo ""
echo "=== Cleanup: kubectl delete job zap-scan ==="
kubectl delete -f "$HERE/zap-scan-job.yaml" --wait=false 2>&1

echo ""
echo "End: $(date +%T)"
