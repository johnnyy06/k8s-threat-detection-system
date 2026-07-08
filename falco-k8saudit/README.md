# falco-k8saudit - stratul de detecție la nivel Kubernetes API / audit

O a doua instanță Falco, **doar-plugin**, care detectează amenințări la nivelul
**Kubernetes API / admission** (plugin-ul `k8saudit`), complementând Falco syscall
(host/runtime) și Suricata (network). Defense-in-depth:

| Strat | Unealtă | Ce vede |
|-------|---------|---------|
| host / syscall | `falco` DaemonSet | exec de procese, fișiere, syscall-uri de rețea |
| network | Suricata (node-2/3) | pachete, semnături de atac web |
| **API / admission** | **`falco-k8saudit`** | **`kubectl apply`, creare pod privileged, acces la secrets, modificări RBAC** |

**De ce contează:** Falco syscall nu poate vedea structural un `kubectl apply`
- doar API server-ul îl vede. Scenariile de atac **01 (container-escape)** și **08
(malicious-deployment)** au documentat acest gap: pasul "deploy pod privileged"
nu producea **nicio detecție**. Acest strat îl închide (`Create Privileged Pod`,
`Create Sensitive Mount Pod`, `Create HostPid/HostNetwork Pod`, `Attach/Exec Pod`,
`K8s Secret Get`, reguli de modificare RBAC etc. - setul stock `k8s_audit_rules.yaml`).

## Arhitectură

```
kube-apiserver (node-1)
  --audit-policy-file --audit-log-path-->  /var/log/kubernetes/audit/audit.log   (file backend)
                                                  |
                          audit-forwarder (Deployment, node-1, `tail -f`)
                                                  |  POST {EventList}
                                                  v
                          Service falco-k8saudit-webhook :9765 (NodePort 30007)
                                                  |
                          falco-k8saudit (plugin k8saudit, webhook listener)
                                                  |  falcosidekick
                                                  v
                          Logstash :5045 --> Elasticsearch `security-*` --> Kibana
```

Evenimentele ajung în **indexul unificat `security-*`**, tag-uite `falco` + `k8s`, și
se disting de Falco syscall prin **`event.provider: k8s_audit`**.

### De ce un forwarder și nu un transport "nativ"

Două căi canonice de live-feed au fost încercate și **ambele au eșuat pe acest cluster
MicroK8s/kubelite** (2026-06-27); forwarder-ul face puntea între cele două părți care
*funcționează* (apiserver-ul scrie fișierul fiabil; webserver-ul webhook al plugin-ului
acceptă EventList-uri):

1. **Driver-ul `file://` al plugin-ului** (`open_params: file:///.../audit.log`): driver-ul
   k8saudit 0.18 **nu** face tail pe un fișier hostPath în care se scrie continuu - citește
   până la EOF la deschidere și ratează append-urile ulterioare. Citirea batch/no-scheme
   funcționează, dar e one-shot. (Dovedit: un `falco -o "plugins[0].open_params=/.../audit.log"`
   one-shot a declanșat `Create Privileged Pod` etc. pe conținutul existent al fișierului.)
2. **Webhook-ul de audit al kube-apiserver** (`--audit-webhook-config-file`): backend-ul
   webhook **nu** se inițializează pe apiserver-ul embedded în kubelite - flag prezent și
   config valid, dar zero metrici `apiserver_audit_webhook_*` și zero livrare (un burst de
   12 evenimente a produs 0 la plugin). Backend-ul de tip fișier (`--audit-log-path`) din
   același fișier de argumente funcționează, deci kubelite *chiar* citește argumentele.

Forwarder-ul e complet decuplat de sănătatea apiserver-ului (apiserver-ul doar scrie un
fișier) și supraviețuiește restart-urilor Falco/forwarder.

## Fișiere

- `audit-policy.yaml` - audit policy minimal (RequestResponse pe write-urile de
  workload/RBAC ca să se captureze spec-ul pod-ului; Metadata pe secrets/configmaps;
  **None** pe get/list/watch + leases + events -> peste 90% din volum aruncat, impact
  neglijabil pe disk-ul bottleneck-uit al node-1). Deployat la
  `/var/snap/microk8s/current/args/audit-policy.yaml`.
- `values/k8saudit-values.yaml` - values Helm pentru release-ul Falco doar-plugin
  (driver off, `controller: deployment`, plugin-uri k8saudit+json, open_params webhook,
  service NodePort). Se folosește **împreună cu** `../falco/config/local-values.yaml`
  partajat (endpoint-ul Logstash).
- `audit-forwarder.yaml` - Deployment-ul-punte `tail -f audit.log | POST` (node-1).

## Deploy / re-deploy

### 1. audit-ul apiserver (node-1, o singură dată)

```bash
# copiaza audit-policy.yaml in /var/snap/microk8s/current/args/audit-policy.yaml
# apoi adauga in /var/snap/microk8s/current/args/kube-apiserver:
#   --audit-policy-file=/var/snap/microk8s/current/args/audit-policy.yaml
#   --audit-log-path=/var/log/kubernetes/audit/audit.log
#   --audit-log-maxsize=50  --audit-log-maxbackup=3  --audit-log-maxage=7
sudo mkdir -p /var/log/kubernetes/audit
sudo snap restart microk8s.daemon-kubelite
sudo microk8s status --wait-ready --timeout 120
```

> Flag-ul rămas `--audit-webhook-config-file` (+ `audit-webhook.yaml`) din încercarea
> abandonată de webhook nativ e **nefuncțional** și poate fi scos pentru curățenie
> (necesită încă un restart kubelite). Nu face rău dacă e lăsat.

### 2. instanța Falco k8saudit + forwarder (de pe laptop)

```bash
cd falco-k8saudit
helm upgrade --install falco-k8saudit falcosecurity/falco -n falco \
  --version 8.0.2 -f values/k8saudit-values.yaml -f ../falco/config/local-values.yaml
kubectl apply -f audit-forwarder.yaml
kubectl rollout status deploy/audit-forwarder -n falco
```

## Verificare

```bash
# reguli incarcate
POD=$(kubectl get pods -n falco -l app.kubernetes.io/instance=falco-k8saudit,app.kubernetes.io/name=falco -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n falco $POD -c falco -- falco -L | grep -i privileged

# test live: creeaza un pod privileged, asteapta o alerta "Create Privileged Pod"
kubectl run k8saudit-test --image=busybox --restart=Never \
  --overrides='{"spec":{"containers":[{"name":"c","image":"busybox","command":["sleep","1"],"securityContext":{"privileged":true}}]}}'
kubectl logs -n falco $POD -c falco --since=1m | grep -i privileged
kubectl delete pod k8saudit-test --force --grace-period=0

# in Elasticsearch (doar evenimentele k8saudit): event.provider = k8s_audit
curl -s "http://10.102.14.31:9200/security-*/_search?size=0" -H 'Content-Type: application/json' -d \
  '{"query":{"bool":{"must":[{"term":{"event.provider":"k8s_audit"}},{"range":{"@timestamp":{"gte":"now-15m"}}}]}}}'
```

## Troubleshooting

- **Nicio alertă dar pod-ul rulează:** verifică lanțul în ordine - (a) e evenimentul în
  fișier? `sudo grep '"privileged":true' /var/log/kubernetes/audit/audit.log` pe node-1;
  (b) e forwarder-ul sus și face POST? `kubectl logs -n falco deploy/audit-forwarder`;
  (c) răspunde webserver-ul plugin-ului? `kubectl exec -n attack-target attack-pod --
  curl -s -o /dev/null -w '%{http_code}' -XPOST http://falco-k8saudit-webhook.falco.svc:9765/k8s-audit -d '{}'`
  (400 = sănătos).
- **`database is locked` la deploy:** bottleneck-ul dqlite de pe node-1 - reîncearcă.
- **Audit log rotat** (50MB): forwarder-ul folosește `tail -f` (fără `-F`); restartează-l:
  `kubectl rollout restart deploy/audit-forwarder -n falco`.