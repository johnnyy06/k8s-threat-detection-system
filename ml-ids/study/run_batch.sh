#!/bin/bash
# Batch controlat pentru studiul DETERMINIST (semnaturi Suricata) vs ML (RandomForest) - network-flow.
# Ruleaza o fereastra benign (liniste) + 3 scenarii cu profile diferite (scan/lateral/web), inregistrand
# pentru fiecare: IP-ul atacatorului + fereastra de timp. Scrie runs.json (consumat de study_det_vs_ml.py).
# Apples-to-apples: ambii detectori pe ACELEASI flow-uri. Falco (host) = complementar, NU in comparatie.
# Ruleaza in fundal (~20 min). Anti-leakage: rulari NOI (flow_id-uri noi, nu in cluster_flows.csv de antrenare).
export KUBECONFIG=/home/tionu/Proiect_licenta/microk8s-licenta
HERE="$(cd "$(dirname "$0")" && pwd)"
AS="$HERE/../../attack-scenarios"
OUT="$HERE/runs.json"
ts(){ date -u +%Y-%m-%dT%H:%M:%SZ; }

ATTACK_POD_IP=$(kubectl get pod attack-pod -n attack-target -o jsonpath='{.status.podIP}')
echo "attack-pod IP: $ATTACK_POD_IP"

# 1) Baseline benign: 4 min de liniste INAINTE de atacuri (separare temporala = fara contaminare).
BL_START=$(ts); echo "[baseline] $BL_START (4 min)"; sleep 240; BL_END=$(ts)

# 2) s05 network-scanning (attacker = attack-pod) - profil scan, multe flow-uri fara semnatura.
echo "[s05] start"; S05_START=$(ts); ( cd "$AS/05-network-scanning" && ./attack.sh ) >/dev/null 2>&1 || true; S05_END=$(ts)
sleep 30

# 3) s11 lateral-movement (attacker = attack-pod) - east-west, mix semnaturi + comportament.
echo "[s11] start"; S11_START=$(ts); ( cd "$AS/11-lateral-movement" && ./attack.sh ) >/dev/null 2>&1 || true; S11_END=$(ts)
sleep 30

# 4) s09 OWASP ZAP (attacker = pod zap-scan, IP capturat live) - exploit web, multe semnaturi ET WEB_SERVER.
echo "[s09] launch"; kubectl delete job zap-scan -n attack-target --ignore-not-found --wait=true >/dev/null 2>&1
kubectl apply -f "$AS/09-owasp-zap/zap-scan-job.yaml" >/dev/null 2>&1
ZAP_IP=""
for i in $(seq 1 50); do ZAP_IP=$(kubectl get pods -n attack-target -l job-name=zap-scan -o jsonpath='{.items[0].status.podIP}' 2>/dev/null); [ -n "$ZAP_IP" ] && break; sleep 3; done
echo "[s09] zap pod IP: $ZAP_IP"
S09_START=$(ts)
kubectl wait --for=condition=complete job/zap-scan -n attack-target --timeout=900s >/dev/null 2>&1 || true
S09_END=$(ts)
kubectl delete job zap-scan -n attack-target --ignore-not-found >/dev/null 2>&1

# 5) Asteapta flush-ul flow-urilor Suricata in ES (timeout flow + Filebeat + Logstash).
echo "[wait] 150s flush ES"; sleep 150

cat > "$OUT" <<EOF
{
  "baseline":  {"start": "$BL_START", "end": "$BL_END"},
  "scenarios": [
    {"id": "s05", "name": "network-scanning", "attacker_ip": "$ATTACK_POD_IP", "start": "$S05_START", "end": "$S05_END"},
    {"id": "s11", "name": "lateral-movement", "attacker_ip": "$ATTACK_POD_IP", "start": "$S11_START", "end": "$S11_END"},
    {"id": "s09", "name": "owasp-zap",        "attacker_ip": "$ZAP_IP",        "start": "$S09_START", "end": "$S09_END"}
  ]
}
EOF
echo "DONE -> $OUT"
cat "$OUT"
