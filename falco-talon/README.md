# Falco Talon — răspuns automat (automated response)

Falco Talon închide bucla detecție→răspuns: primește evenimentele Falco prin **falcosidekick** și
execută acțiuni Kubernetes (label / izolare prin NetworkPolicy / terminate) pe pod-ul vinovat.

```
Falco (DaemonSet) → falcosidekick (output `talon`) → Falco Talon (ns falco-system) → acțiuni K8s
                                                                                    → notifier Elasticsearch → Kibana
```

## Componente în repo

| Fișier | Rol |
|---|---|
| `values/talon-values.yaml` | Values pentru chart-ul oficial `falcosecurity/falco-talon` 0.4.0 (deployment, RBAC, NATS embedded, **regulile** prin `config.rulesOverride`). |
| `config/config.yaml` | `config.yaml` NATIV Talon, aplicat ca **override** peste secret-ul `falco-talon-config` (vezi „Bug-uri chart" mai jos). Conține notifier-ul ES + `leader_election: false`. |
| `talon-demo-pod.yaml` | Pod throwaway `talon-demo` pentru demo-ul de `terminate` (fals `xmrig` = `sleep`). |

Regulile sunt în `values/talon-values.yaml` (`config.rulesOverride`), mapate pe regulile custom
`K8S_THREAT:*` ale Falco:
- **Reverse shell** (`K8S_THREAT: Reverse Shell - Command Pattern in Container`) → `kubernetes:label`
  (`compromised=true`) + `kubernetes:networkpolicy` (izolare) — **ne-distructiv, reversibil**, sigur pe attack-pod.
- **Crypto mining** (`K8S_THREAT: Crypto Mining Binary Detected`) **scoped pe `k8s.pod.name=talon-demo`**
  → `kubernetes:terminate` — letal, doar pe pod-ul demo, ca attack-pod (scenariul 02) să nu fie omorât.

## Deploy

```bash
# 1. Chart-ul Talon (în ns falco-system, care există deja)
helm install falco-talon falcosecurity/falco-talon -n falco-system --version 0.4.0 \
  -f falco-talon/values/talon-values.yaml

# 2. OBLIGATORIU: override config secret (bug-uri chart, vezi mai jos)
kubectl create secret generic falco-talon-config -n falco-system \
  --from-file=config.yaml=falco-talon/config/config.yaml --dry-run=client -o yaml | kubectl apply -f -
kubectl rollout restart deploy/falco-talon -n falco-system

# 3. Conectarea falcosidekick → Talon (output `talon` în falco/config/local-values.yaml):
#      falcosidekick.config.talon.address: http://falco-talon.falco-system:2803
#    apoi upgrade la release-ul falco (DOAR Deployment-ul falcosidekick se reia; DaemonSet-ul NU):
cd falco/config && helm upgrade falco falcosecurity/falco -n falco --version 8.0.2 \
  -f custom-values.yaml -f local-values.yaml
```

Verificare sănătate:
```bash
POD=$(kubectl get pods -n falco-system -l app.kubernetes.io/name=falco-talon -o jsonpath='{.items[0].metadata.name}')
kubectl logs -n falco-system $POD | grep -iE 'rule.*loaded|listening|elasticsearch|leader'
# astept: "2 rule(s) ... loaded", "up and listening on 0.0.0.0:2803", FĂRĂ eroare elasticsearch/leader
kubectl logs -n falco -l app.kubernetes.io/name=falcosidekick | grep 'Enabled Outputs'  # => [Webhook Talon]
```

## ⚠️ Bug-uri în chart-ul falco-talon 0.4.0 (material Cap D — limitări)

`templates/secrets.yaml` (care randează `config.yaml`) are 2 bug-uri care fac imposibilă
configurarea corectă DOAR prin `-f values`, de aceea aplicăm `config/config.yaml` ca override:

1. **`leader_election: {{ default true ...leaderElection }}`** — funcția Helm `default true`
   tratează `false` drept „gol" și revine la `true`. Deci `leaderElection: false` din values e ignorat.
   (Pe control-plane-ul lent al cluster-ului, leader election-ul dă `lease ... context deadline
   exceeded` — vrem `false` cu o singură replică.)
2. **`create_index_template` / `number_of_shards` / `number_of_replicas`** citesc din calea
   `.notifiers.LOKI.*` în loc de `.notifiers.ELASTICSEARCH.*` → ies goale → notifier-ul ES pică la
   init cu `invalid character 'u' looking for beginning of object key string`.

Notifier-ul ES are nevoie și de `create_index_template: false` (ES 8.19 respinge API-ul de
index-template folosit de Talon; indexul `falco-talon-YYYY.MM.DD` se creează oricum automat).

## Validare end-to-end

```bash
# Calea reversibilă (attack-pod): reverse shell → label + NetworkPolicy
kubectl exec -n attack-target attack-pod -- bash -c ':; # /dev/tcp/10.0.0.1/4444'
kubectl get pod attack-pod -n attack-target --show-labels   # compromised=true
kubectl get netpol -n attack-target                         # netpol 'attack-pod'
# CLEANUP (obligatoriu, altfel izolarea blochează scenariile viitoare):
kubectl delete netpol attack-pod -n attack-target
kubectl label pod attack-pod -n attack-target compromised-

# Calea letală (pod demo): crypto mining → terminate
kubectl apply -f falco-talon/talon-demo-pod.yaml
kubectl get pod talon-demo -n attack-target   # → Terminating → NotFound

# Răspunsurile în ES/Kibana (index separat de `security-*`):
curl -s "http://10.102.14.31:9200/falco-talon*/_search?size=10" | python3 -m json.tool
```

Latență tipică detecție→acțiune: ~3–5s.
