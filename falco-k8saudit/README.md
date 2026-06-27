# falco-k8saudit - Kubernetes API / audit detection layer

A second, **plugin-only** Falco instance that detects threats at the **Kubernetes
API / admission layer** (the `k8saudit` plugin), complementing the syscall Falco
(host/runtime) and Suricata (network). Defense-in-depth:

| Layer | Tool | Sees |
|-------|------|------|
| host / syscall | `falco` DaemonSet | process exec, file, network syscalls |
| network | Suricata (node-2/3) | packets, web-attack signatures |
| **API / admission** | **`falco-k8saudit`** | **`kubectl apply`, privileged-pod creation, secret access, RBAC changes** |

**Why this matters:** the syscall Falco structurally cannot see a `kubectl apply`
- only the API server does. Attack scenarios **01 (container-escape)** and **08
(malicious-deployment)** documented this gap: the "deploy a privileged pod" step
produced **no detection**. This layer closes it (`Create Privileged Pod`,
`Create Sensitive Mount Pod`, `Create HostPid/HostNetwork Pod`, `Attach/Exec Pod`,
`K8s Secret Get`, RBAC-change rules, etc. - the stock `k8s_audit_rules.yaml`).

## Architecture (as actually deployed)

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

Events land in the **unified `security-*` index**, tagged `falco` + `k8s`, and are
distinguished from syscall-Falco by **`event.provider: k8s_audit`**.

### Why a forwarder and not a "native" transport

Two canonical live-feed paths were tried and **both failed on this MicroK8s/kubelite
cluster** (2026-06-27); the forwarder bridges the two parts that *do* work
(apiserver writes the file reliably; the plugin's webhook server accepts EventLists):

1. **`file://` plugin driver** (`open_params: file:///.../audit.log`): the k8saudit
   0.18 driver does **not** tail an appended hostPath file - it reads to EOF at open
   and misses subsequent appends. Batch/no-scheme read works but is one-shot.
   (Proven: a one-shot `falco -o "plugins[0].open_params=/.../audit.log"` fired
   `Create Privileged Pod` etc. on the existing file content.)
2. **kube-apiserver audit webhook** (`--audit-webhook-config-file`): the webhook
   backend does **not** initialize on the kubelite-embedded apiserver - flag present
   and config valid, but no `apiserver_audit_webhook_*` metrics and zero delivery
   (a 12-event burst produced 0 at the plugin). The `--audit-log-path` file backend
   in the same args file works fine, so kubelite *does* read the args.

The forwarder is fully decoupled from apiserver health (apiserver just writes a
file) and survives Falco/forwarder restarts.

## Files

- `audit-policy.yaml` - minimal audit policy (RequestResponse on workload/RBAC
  writes so pod specs are captured; Metadata on secrets/configmaps; **None** on
  get/list/watch + leases + events -> >90% volume dropped, tiny disk impact on the
  bottlenecked node-1). Deployed to `/var/snap/microk8s/current/args/audit-policy.yaml`.
- `values/k8saudit-values.yaml` - Helm values for the plugin-only Falco release
  (driver off, `controller: deployment`, k8saudit+json plugins, webhook open_params,
  NodePort service). Use **with** the shared `../falco/config/local-values.yaml`
  (Logstash endpoint).
- `audit-forwarder.yaml` - the `tail -f audit.log | POST` bridge Deployment (node-1).

## Deploy / re-deploy

### 1. apiserver audit (node-1, one-time)

```bash
# copy audit-policy.yaml to /var/snap/microk8s/current/args/audit-policy.yaml
# then add to /var/snap/microk8s/current/args/kube-apiserver:
#   --audit-policy-file=/var/snap/microk8s/current/args/audit-policy.yaml
#   --audit-log-path=/var/log/kubernetes/audit/audit.log
#   --audit-log-maxsize=50  --audit-log-maxbackup=3  --audit-log-maxage=7
sudo mkdir -p /var/log/kubernetes/audit
sudo snap restart microk8s.daemon-kubelite
sudo microk8s status --wait-ready --timeout 120
```

> The leftover `--audit-webhook-config-file` flag (+ `audit-webhook.yaml`) from the
> abandoned native-webhook attempt is **non-functional** and can be removed for
> cleanliness (requires another kubelite restart). It does no harm if left.

### 2. Falco k8saudit instance + forwarder (laptop)

```bash
cd falco-k8saudit
helm upgrade --install falco-k8saudit falcosecurity/falco -n falco \
  --version 8.0.2 -f values/k8saudit-values.yaml -f ../falco/config/local-values.yaml
kubectl apply -f audit-forwarder.yaml
kubectl rollout status deploy/audit-forwarder -n falco
```

## Verify

```bash
# loaded rules
POD=$(kubectl get pods -n falco -l app.kubernetes.io/instance=falco-k8saudit,app.kubernetes.io/name=falco -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n falco $POD -c falco -- falco -L | grep -i privileged

# live test: create a privileged pod, expect a "Create Privileged Pod" alert
kubectl run k8saudit-test --image=busybox --restart=Never \
  --overrides='{"spec":{"containers":[{"name":"c","image":"busybox","command":["sleep","1"],"securityContext":{"privileged":true}}]}}'
kubectl logs -n falco $POD -c falco --since=1m | grep -i privileged
kubectl delete pod k8saudit-test --force --grace-period=0

# in Elasticsearch (only k8saudit events): event.provider = k8s_audit
curl -s "http://10.102.14.31:9200/security-*/_search?size=0" -H 'Content-Type: application/json' -d \
  '{"query":{"bool":{"must":[{"term":{"event.provider":"k8s_audit"}},{"range":{"@timestamp":{"gte":"now-15m"}}}]}}}'
```

## Troubleshooting

- **No alerts but pod runs:** check the chain in order - (a) is the event in the
  file? `sudo grep '"privileged":true' /var/log/kubernetes/audit/audit.log` on node-1;
  (b) is the forwarder up and POSTing? `kubectl logs -n falco deploy/audit-forwarder`;
  (c) does the plugin webserver answer? `kubectl exec -n attack-target attack-pod --
  curl -s -o /dev/null -w '%{http_code}' -XPOST http://falco-k8saudit-webhook.falco.svc:9765/k8s-audit -d '{}'`
  (400 = healthy).
- **`database is locked` during deploy:** node-1 dqlite bottleneck - retry.
- **Audit log rotated** (50MB): the forwarder uses `tail -f` (no `-F`); restart it:
  `kubectl rollout restart deploy/audit-forwarder -n falco`.
