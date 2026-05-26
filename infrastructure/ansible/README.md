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

IP-urile reale ale nodurilor și ale serviciilor LoadBalancer sunt în `inventories/hosts.ini` (gitignored). Înlocuiește placeholder-urile de mai jos cu valorile tale din `hosts.ini` și din `kubectl get svc -n vulnerable-apps`.

```bash
# Kibana (ELK pe node-4)
ssh -L 5601:localhost:5601 ubuntu@<NODE4_FLOATING_IP>
# → http://localhost:5601

# DVWA (LoadBalancer service)
ssh -L 8080:<DVWA_LB_IP>:80 ubuntu@<JUMP_HOST>
# → http://localhost:8080

# Juice Shop (LoadBalancer service)
ssh -L 8081:<JUICE_SHOP_LB_IP>:3000 ubuntu@<JUMP_HOST>
# → http://localhost:8081
```

## Filtre utile în Kibana (Discover)

```
tags: "falco"         # Alerte Falco
tags: "suricata"      # Alerte Suricata
priority: "Critical"  # Alerte critice Falco
rule: *               # Toate evenimentele cu regulă Falco
```
