# Studiu: Determinist (semnaturi Suricata) vs ML (RandomForest) — network-flow

Apples-to-apples: ambii detectori pe ACELEASI flow-uri Suricata. Ground truth din atacuri
controlate (ATTACK = attacker IP in fereastra; BENIGN = fereastra liniste, separata temporal).
Falco (host/syscall) e complementar — NU intra in aceasta comparatie cantitativa.

Dataset: 202 flow-uri ATTACK (din 3 scenarii) + 116 BENIGN.

## Rezultate per scenariu (vs acelasi set BENIGN)

| Scenariu | #ATTACK | Determinist (Suricata) | ML (RandomForest) |
|---|---|---|---|
| s05 (network-scanning) | 56 | P=1.000 R=0.232 F1=0.377 acc=0.750 | P=1.000 R=0.982 F1=0.991 acc=0.994 |
| s11 (lateral-movement) | 11 | P=1.000 R=0.364 F1=0.533 acc=0.945 | P=1.000 R=1.000 F1=1.000 acc=1.000 |
| s09 (owasp-zap) | 135 | P=1.000 R=0.719 F1=0.836 acc=0.849 | P=1.000 R=0.933 F1=0.966 acc=0.964 |

## Agregat (toate scenariile)

| Detector | Precision | Recall | F1 | Accuracy |
|---|---|---|---|---|
| Determinist (Suricata) | 1.000 | 0.564 | 0.722 | 0.723 |
| ML (RandomForest) | 1.000 | 0.950 | 0.975 | 0.969 |

## Complementaritate (pe flow-urile ATTACK)

- **both** (ambii prind): 109 (54.0%)
- **doar ML** (ML prinde, semnaturile rateaza): 83 (41.1%)
- **doar determinist** (semnatura prinde, ML rateaza): 5 (2.5%)
- **niciunul** (ratat de ambii): 5 (2.5%)
- **recall uniune** (det SAU ml): **0.975** — vs det 0.564, ml 0.950

> Concluzia complementaritatii: stratul combinat (semnaturi + ML) prinde mai mult decat oricare singur.

## Caveat (onestitate metodologica)
- BENIGN-ul e dominat de trafic de infra (VXLAN/calico/DNS), usor separabil -> scorurile sunt
  optimiste; relevanta e COMPARATIA dintre detectori, nu valorile absolute.
- Evaluare in-environment (instante noi ale tipurilor de atac antrenate); generalizarea intre
  medii e tratata separat (studiul cross-dataset, RESULTS.md).
- s07 (exfil egress) NU e inclus aici din cauza SNAT-ului Calico (atribuire per-pod pierduta la egress);
  scenariile alese (s05 scan, s11 lateral, s09 web) au atacatorul ca sursa spre tinte interne = atribuire curata.
