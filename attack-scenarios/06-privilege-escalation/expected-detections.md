# Scenariul 6 — Privilege Escalation (T1548)

**MITRE ATT&CK:** T1548 (Abuse Elevation Control Mechanism)

## Pași de atac

1. `touch /tmp/escalation && chmod 4755 /tmp/escalation` — setuid bit via mode numeric (4755)
2. `chmod u+s /tmp/escalation` — setuid bit via mode simbolic
3. `chmod 6755 /tmp/escalation` — setuid + setgid via mode numeric
4. `su -c whoami` — invocare `su` (eșuează fără parolă, dar proc spawn declanșează regula)
5. `apt-get update && apt-get install -y sudo` — descărcare + instalare tool de escalare
6. `sudo whoami` — invocare `sudo`

## Rezultate finale (după 2 iterații de tuning)

| Regulă | Priority | Count |
|---|---|---|
| `K8S_THREAT: Privilege Escalation via Setuid/Setgid` | Critical | 3 |
| `K8S_THREAT: Sudo or Su Usage in Container` | Warning | 1 |
| `K8S_THREAT: Package Manager in Running Container` | Warning | 2 |
| `Drop and execute new binary in container` (default) | Critical | 1 |
| **Total** | | **7** |

**Detection rate**: 100% (toți 6 pași detectați, unii prin reguli multiple)
**False positive rate**: 0%

## Procesul de tuning

| Iterație | Modificare | Total | True+ | False+ |
|---|---|---|---|---|
| A (baseline) | reguli K8S_THREAT active după macro fix | 8 | 7 | 1 (dpkg-preconfigu citește /etc/shadow legitim) |
| B | extinde `allowed_shadow_readers` cu dpkg, dpkg-preconfigu, apt, apt-get | 7 | 7 | 0 |

## Discoveries (relevant pentru Cap D și Cap 6)

### 1. Bonus default-rule descoperită — `Drop and execute new binary in container`
La pasul 6 (`sudo whoami`), regula custom `Sudo or Su Usage` NU a tras pentru `sudo`. În schimb, regula default Falco `Drop and execute new binary in container` a tras prima:
- Falco compară inode creation time (ctime) al binarului cu timpul de pornire al containerului
- Sudo a fost instalat post-startup → ctime fresh → detectat ca "binary nou"
- Aceasta este o **regulă comportamentală sofisticată** care complementează regulile pattern-based

### 2. Rule precedence — al doilea caz observat
Same problem ca scenariul 4 — when default rule and custom rule overlap, default rule fires first if defined earlier in evaluation order. Pattern-ul se repetă → este **structural**, nu un bug izolat.

### 3. False positive structural — package install postinst scripts citesc /etc/shadow
`dpkg-preconfigu` (truncat din `dpkg-preconfigure`), parte din procesul standard de instalare a pachetelor `.deb`, citește `/etc/shadow` în mod legitim pentru a verifica utilizatorii sistemului.
**Fix aplicat**: extins `allowed_shadow_readers` cu `dpkg`, `dpkg-preconfigu`, `apt`, `apt-get`.

### 4. Coverage cross-scenarii — apt-get în scenariul 6 declanșează regula scenariului 8
Pasul 5 (apt-get install) declanșează `K8S_THREAT: Package Manager in Running Container` care e tag-uit `scenario_08`. Aceasta confirmă că **pattern-urile de atac se suprapun natural** între scenarii — observabil pentru Cap E "Lessons Learned".

## Cross-tool correlation
**Mediu** — apt-get update generează trafic HTTP spre archive.ubuntu.com. Suricata vede traficul dar fără signature match (trafic legitim de tip apt). Util ca **demonstrație de evidence cross-layer** chiar și în absența detecției signature.

## False negatives confirmate
- Setuid prin `chown` + `chmod` separate (nu folosim acest pattern)
- Privilege escalation prin kernel exploit (CVE-uri locale) — nedetectabil cu reguli statice de syscall
- Privilege escalation indirectă prin binari setuid existenți deja (ex: `/usr/bin/passwd`)
