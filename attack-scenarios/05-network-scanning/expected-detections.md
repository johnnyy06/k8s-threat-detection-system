# Scenariul 5 — Network Scanning (T1046)

**MITRE ATT&CK:** T1046 (Network Service Discovery)

**Primul scenariu cu cross-tool real Falco + Suricata.**

## Pași de atac

1. `apt-get install -y nmap` — descărcare + instalare nmap (tool de scanare)
2. `nmap -sT -p 1-1000 10.152.183.1` — TCP connect scan, primele 1000 porturi pe Kubernetes API svc
3. `nmap -sS -p 22,80,443,8080,3306 10.1.139.66` — SYN scan pe DVWA pod (porturi tipice web/db)
4. `nmap -sV -p 80 10.1.139.66` — service version detection pe DVWA (banner grabbing)
5. `nc -zv 10.1.247.31 80 8080 8443` — netcat connect scan pe Falco daemon pod

## Reguli așteptate să tragă

### Falco — reguli custom

| Regulă | Priority | Pași |
|---|---|---|
| `K8S_THREAT: Network Scanning Tool in Container` | Warning | 2, 3, 4 (nmap), 5 (nc) |
| `K8S_THREAT: Package Manager in Running Container` | Warning | 1 (apt-get) |

### Falco — reguli default
Posibil:
- `Drop and execute new binary in container` (Critical) — la prima execuție a binarului `nmap` post-install

### Suricata — semnături așteptate

| Tip semnătură | Pași |
|---|---|
| `ET SCAN Nmap TCP` (sau similar) | 2 (TCP connect scan) |
| `ET SCAN Possible Nmap User-Agent` | 4 (-sV banner grab) |
| `ET POLICY SUSPICIOUS Possible Nmap Scan` | 2, 3, 4 |
| `ET SCAN Potential SSH Scan` | 3 (port 22) — posibil |

## Cross-tool correlation
**STRONG** — fiecare scan trebuie să fie vizibil:
- Falco: detectează lansarea tool-ului în container (syscall layer)
- Suricata: detectează pattern-urile de pachete pe rețea (network layer)

Pentru fiecare comandă nmap, ne așteptăm la **min. 2 surse de detecție** (1 Falco + ≥1 Suricata).

## False negatives așteptate
- Scan **slow** (`-T0`, `-T1`) — Suricata poate să nu prindă (sub threshold)
- Scan via **proxy intern** (kube-proxy NAT) — Suricata pe interfața fizică ar putea să nu vadă tunelele VXLAN decap-ate
- Scanări orchestrate prin K8s svc (nu pod IP direct) — depinde de plasarea Suricata sensors

## Cifre așteptate
- Falco: 6-8 detecții (4-5 nmap + 1 nc + 1 apt-get + posibil 1 default)
- Suricata: 20-50+ alerts (depinde de regulile ET active și volumul de pachete scan)
- **Total**: 25-60 evenimente cross-tool

Pentru Cap D, asta dă o tabelă bogată "events per layer per scan step".
