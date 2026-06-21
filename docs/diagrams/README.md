# Diagrame teză — surse & convenții

Surse versionate pentru lucrările grafice (Cap B/C — arhitectură, fluxuri, interconectare).

## Fișiere
| Fișier | Tool | Conține |
|---|---|---|
| `architecture.drawio` | **draw.io** | Schelet arhitectură 4-noduri (de rafinat: layout + icoane oficiale) |
| `flows.md` | **Mermaid** | 1) blueprint arhitectură · 2) flux colectare loguri+alertare · 3) interconectare IDS/Falco/ELK pe straturi · 4) secvență atac→detecție→răspuns · 5) pipeline metrici Prometheus+Grafana (pull-based) |

## draw.io — cum lucrezi
- **VSCode:** instalează extensia *Draw.io Integration* (`hediet.vscode-drawio`) → deschizi `architecture.drawio` direct, editezi vizual, se salvează ca XML (version-controllable).
- **Browser:** <https://app.diagrams.net> → *Open Existing Diagram* → `architecture.drawio`.
- **Icoane oficiale:** *More Shapes…* → bifează **Networking > Kubernetes** (+ Azure/AWS dacă vrei). Pentru Elastic/Falco/Suricata: importă logo-urile SVG (drag&drop) sau *Edit Style*.
- **Export pentru tipar:** *File > Export as > SVG* (sau PDF) → vector, clar la orice zoom. **Evită PNG** (se pixelează în teză).

## Mermaid — cum randezi
- **VSCode:** extensia *Markdown Preview Mermaid Support* → preview pe `flows.md`.
- **GitHub:** se randează automat în preview-ul fișierului.
- **Export vector:** <https://mermaid.live> (paste blocul → Export SVG/PNG), sau CLI:
  ```bash
  npm i -g @mermaid-js/mermaid-cli
  mmdc -i flows.md -o flows.svg     # exportă fiecare diagramă
  ```

## Convenții vizuale (păstrează-le consistente în toate diagramele)
- 🟦 albastru = **Falco** (runtime/syscall) · 🟥 roșu = **Suricata** (network IDS) ·
  🟩 verde = **ELK** (colectare/corelare) · 🟨 galben = **Falco Talon** (răspuns) · ⬜ alb = workload/țintă.
- Linie continuă = flux de loguri/alerte; linie punctată = acces/atac/notifier.
- Pune mereu **legendă** + **IP-uri/porturi** reale (credibilitate tehnică).

## Recomandare împărțire (din discuție)
- **Arhitectura completă** + **interconectarea IDS/Falco/ELK** → draw.io (layout fin, icoane).
- **Fluxurile de alertare/colectare** → Mermaid (pipeline ușor de iterat ca text).

Datele de arhitectură (topologie, porturi, plasare senzori) sunt în `CLAUDE.md` și
`suricata/README.md` / `falco-talon/README.md` — sursa de adevăr pentru diagrame.
