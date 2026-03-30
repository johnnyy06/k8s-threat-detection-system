# Ansible — Sistem integrat de detecție amenințări Kubernetes

Playbook-uri Ansible pentru recrearea rapidă a infrastructurii.

## Structura proiectului

```
ansible-k8s-security/
├── inventories/
│   └── hosts.ini                   # IP-uri noduri
├── group_vars/
│   └── all.yml                     # Variabile globale
├── files/                          # Fișierele de configurație exacte din cluster
│   ├── talon-config.yaml           # Falco Talon — ConfigMap
│   ├── talon-deployment.yaml       # Falco Talon — Deployment + Service + RBAC
│   ├── vulnerable-apps.yaml        # DVWA + Juice Shop
│   ├── suricata-local.rules        # Reguli custom Suricata
│   └── logstash-security.conf      # Pipeline Logstash
├── playbooks/
│   ├── site.yml                    # Master playbook (rulează totul în ordine)
│   ├── node1_control_plane.yml
│   ├── node2_security.yml
│   ├── node3_application.yml
│   ├── node4_monitoring.yml
│   └── health_check.yml
└── README.md
```

## Arhitectura infrastructurii

| Nod    | Rol                         |
| ------ | --------------------------- |
| node-1 | Control Plane + Falco Talon |
| node-2 | Suricata IDS/IPS            |
| node-3 | Aplicații vulnerabile       |
| node-4 | ELK Stack                   |

**Notă:** Falco rulează ca DaemonSet pe TOATE nodurile.

## Flux de date

```
Suricata (node-2) → Filebeat → Logstash:5044 ─┐
k8s-apps (node-3) → Filebeat → Logstash:5044 ─┼→ Elasticsearch → Kibana
Falco (toate)  → Falco Sidekick → Logstash:5045 ─┘
                                    index: security-YYYY.MM.DD
```

## Utilizare

```bash
# Verificare conectivitate SSH
ansible -i inventories/hosts.ini all -m ping

# Recreare completă a infrastructurii
ansible-playbook -i inventories/hosts.ini playbooks/site.yml

# Nod specific
ansible-playbook -i inventories/hosts.ini playbooks/node4_monitoring.yml

# Verificare stare fără modificări
ansible-playbook -i inventories/hosts.ini playbooks/health_check.yml

# Dry-run
ansible-playbook -i inventories/hosts.ini playbooks/site.yml --check
```

## Acces servicii prin SSH tunnel

```bash
# Kibana
ssh -L 5601:localhost:5601 ubuntu@10.102.14.31
# → http://localhost:5601

# DVWA
ssh -L 8080:10.11.0.200:80 ubuntu@10.102.11.79
# → http://localhost:8080

# Juice Shop
ssh -L 8081:10.11.0.201:3000 ubuntu@10.102.11.79
# → http://localhost:8081
```

## Filtre utile în Kibana (Discover)

```
tags: "falco"         # Alerte Falco
tags: "suricata"      # Alerte Suricata
priority: "Critical"  # Alerte critice Falco
rule: *               # Toate evenimentele cu regulă Falco
```
