# Ansible — deploy „4 VM-uri goale → nucleul de detecție"

Playbook-uri Ansible care ridică **nucleul de detecție actual** al sistemului pornind de la 4 VM-uri
Ubuntu goale. Reflectă starea reală a clusterului (nu versiunea inițială): Suricata pe **node-2 ȘI
node-3**, Falco cu **regulile custom K8S_THREAT**, Falco Talon prin **Helm 0.4.0**.

> ⚠️ **Scope (Tier 2 — „nucleul de detecție"):** acest set NU include, deliberat: stratul **k8saudit**
> (audit API), pipeline-ul **ML/IDS**, stack-ul **Prometheus + Grafana**, importul **dashboard-urilor
> Kibana**. Vezi „Ce rămâne manual" mai jos. Aceste componente trăiesc ca artefacte separate în repo
> (`falco-k8saudit/`, `ml-ids/`, `observability/`, `dashboards/`) și se aplică peste sistemul de bază.

## Structură

```
infrastructure/ansible/
├── inventories/hosts.ini(.example)     # ansible_host (SSH) + internal_ip (10.11.0.x)
├── group_vars/all.yml(.example)        # IP-uri, porturi, CIDR, versiuni, HOME_NET
├── files/                              # config-uri VERBATIM din sursele de adevar din repo
│   ├── falco-custom-values.yaml        # <- falco/config/custom-values.yaml (reguli K8S_THREAT)
│   ├── talon-values.yaml               # <- falco-talon/values/ (chart 0.4.0)
│   ├── talon-config.yaml               # <- falco-talon/config/config.yaml (override secret)
│   ├── logstash-security.conf          # <- elk/logstash/ (pipeline ECS/MITRE actual)
│   ├── suricata-local.rules            # <- suricata/rules/ (sid 1000010-12)
│   ├── logrotate-suricata.conf         # <- suricata/systemd-sensors/
│   └── vulnerable-apps.yaml            # DVWA + Juice Shop
├── templates/
│   ├── filebeat-suricata.yml.j2        # eve.json -> Logstash (node=inventory_hostname)
│   └── falco-local-values.yaml.j2      # endpoint Logstash + adresa Talon
├── tasks/suricata_sensor.yml           # senzor Suricata + Filebeat (partajat node-2/3)
├── playbooks/
│   ├── bootstrap_cluster.yml           # * install MicroK8s + join (piesa care lipsea)
│   ├── node4_monitoring.yml            # ELK + logstash-security.conf
│   ├── node2_security.yml              # senzor Suricata (import tasks)
│   ├── node3_application.yml           # senzor Suricata (import tasks) + workloads
│   ├── node1_control_plane.yml         # addons, labels, Falco custom, Talon Helm, app
│   ├── site.yml                        # master (bootstrap -> node4 -> node2 -> node3 -> node1)
│   └── health_check.yml
└── README.md
```

## Topologie

| Nod | Rol | Componente ansible |
|---|---|---|
| node-1 | Control Plane | MicroK8s seed, addons, Falco (custom-values), Talon (Helm), app |
| node-2 | Security worker | senzor Suricata + Filebeat |
| node-3 | Application worker | **senzor Suricata** + Filebeat + workloads (DVWA/Juice Shop) |
| node-4 | Monitoring worker | ELK (Elasticsearch + Kibana + Logstash) |

Falco rulează ca **DaemonSet pe toate nodurile**. Suricata = systemd pe **node-2 + node-3**
(sensor-near-target). ELK = systemd pe node-4 (în afara K8s).

## Flux de date (starea actuală)

```
Suricata (node-2) → Filebeat ─┐
Suricata (node-3) → Filebeat ─┼→ Logstash:5044 ─┐
Falco (toate) → falcosidekick → Logstash:5045 ──┴→ Elasticsearch (security-*) → Kibana
Falco → falcosidekick (output talon) → Falco Talon → acțiuni K8s + index falco-talon-*
```

## Utilizare

```bash
# 0. pregatire: completeaza inventarul + variabilele
cp inventories/hosts.ini.example inventories/hosts.ini    # + editeaza ansible_host/internal_ip
cp group_vars/all.yml.example group_vars/all.yml          # + editeaza IP-uri/CIDR

# 1. conectivitate
ansible -i inventories/hosts.ini all -m ping

# 2. deploy complet (ordinea conteaza — bootstrap PRIMUL)
ansible-playbook -i inventories/hosts.ini playbooks/site.yml

# doar bootstrap-ul de cluster
ansible-playbook -i inventories/hosts.ini playbooks/bootstrap_cluster.yml
# doar un nod
ansible-playbook -i inventories/hosts.ini playbooks/node4_monitoring.yml
# verificare stare (fara modificari)
ansible-playbook -i inventories/hosts.ini playbooks/health_check.yml
```

## Ce rămâne manual (out of scope Tier 2)

După ce sistemul de bază e sus, aceste componente se aplică separat (au propriile runbook-uri în repo):

1. **k8saudit** (detecție API/admission) — `falco-k8saudit/README.md` (audit policy pe apiserver +
   falco-k8saudit prin Helm + audit-forwarder).
2. **ML/IDS** (RandomForest pe flow-uri Suricata) — `ml-ids/README.md`.
3. **Prometheus + Grafana** (metrici cluster) — `observability/` (2 chart-uri Helm).
4. **Dashboard-uri + data views Kibana** — `dashboards/` (scripturi Python + API).

## Note / limitări

- **Cluster non-HA:** node-1 = singurul control-plane; node-2/3/4 = workers (`microk8s join --worker`).
- **`suricata.yaml`:** editat in-place (replace/lineinfile) peste config-ul stock. Dacă structura
  stock diferă între versiuni, regex-urile din `tasks/suricata_sensor.yml` pot necesita ajustare;
  sursa de adevăr rămâne configul de pe node-2 (vezi `suricata/README.md`).
- **Bug-uri chart Talon 0.4.0:** config-ul nativ (`talon-config.yaml`) se aplică drept **override**
  al secret-ului `falco-talon-config` (chart-ul are 2 bug-uri în `secrets.yaml`). Vezi
  `falco-talon/README.md`.
- **Reachability:** de pe laptop, IP-urile interne `10.11.0.x` nu sunt rutabile — folosește IP-uri
  flotante pentru `ansible_host` (vezi `hosts.ini`).
```