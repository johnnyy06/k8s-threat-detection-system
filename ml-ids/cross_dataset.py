#!/usr/bin/env python3
"""
cross_dataset.py — studiu de DOMAIN SHIFT: antrenez RF pe un dataset, testez pe celalalt.
Ambele sunt features CICFlowMeter, dar din versiuni diferite (nume usor diferite) => armonizez
pe setul COMUN de features (normalizare nume + token sort). Clasificare binara (BENIGN vs ATTACK).

Demonstreaza empiric ca un model antrenat pe un dataset NU generalizeaza pe alt mediu/distributie
(F1 scade puternic cross-dataset vs within-dataset). Material pentru Cap E (limitari ML / domain shift).

Rulare: ./.venv/bin/python cross_dataset.py
"""
import os, re, gc, glob, time
import numpy as np, pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score, accuracy_score, classification_report

HERE = os.path.dirname(os.path.abspath(__file__)); RS = 42

def norm(c):
    """Cheie canonica pt potrivirea coloanelor intre versiuni CICFlowMeter (token-sorted)."""
    c = c.strip().lower()
    c = c.replace("total length of", "totlen").replace("backward", "bwd").replace("forward", "fwd")
    c = re.sub(r"packets?", "pkt", c); c = re.sub(r"bytes?", "byte", c)
    toks = sorted(re.findall(r"[a-z0-9]+", c))   # token sort => ignora ordinea cuvintelor
    return "".join(toks)

def clean(df):
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    for c in df.select_dtypes(include=["float64"]).columns:
        df[c] = df[c].astype("float32")
    return df

def load_ids2017():
    parts = []
    for f in sorted(glob.glob(f"{HERE}/CIC-IDS2017/MachineLearningCSV/*.csv")):
        d = pd.read_csv(f, low_memory=False, encoding="latin-1")
        d.columns = [c.strip() for c in d.columns]; parts.append(d)
    df = pd.concat(parts, ignore_index=True)
    y = (df["Label"].astype(str).str.strip() != "BENIGN").astype("int8")
    X = df.drop(columns=["Label"]).select_dtypes(include=[np.number])
    Xy = clean(pd.concat([X, y.rename("y")], axis=1))
    return Xy.drop(columns=["y"]), Xy["y"]

def load_unsw():
    X = pd.read_csv(f"{HERE}/CIC-UNSW-NB15/Data.csv", low_memory=False)
    X.columns = [c.strip() for c in X.columns]
    y = (pd.read_csv(f"{HERE}/CIC-UNSW-NB15/Label.csv")["Label"] != 0).astype("int8").reset_index(drop=True)
    X = X.select_dtypes(include=[np.number]).reset_index(drop=True)
    Xy = clean(pd.concat([X, y.rename("y")], axis=1))
    return Xy.drop(columns=["y"]), Xy["y"]

def harmonize(Xa, Xb):
    """Aliniaza ambele pe setul comun de features (dupa cheia normalizata); returneaza cu coloane canonice."""
    na = {norm(c): c for c in Xa.columns}; nb = {norm(c): c for c in Xb.columns}
    common = sorted(set(na) & set(nb))
    Xa2 = Xa[[na[k] for k in common]].copy(); Xa2.columns = common
    Xb2 = Xb[[nb[k] for k in common]].copy(); Xb2.columns = common
    return Xa2, Xb2, common

def fit_rf(X, y):
    clf = RandomForestClassifier(n_estimators=100, n_jobs=-1, class_weight="balanced", random_state=RS)
    clf.fit(X, y); return clf

def main():
    print("incarc CIC-IDS2017..."); Xi, yi = load_ids2017(); print(f"  {Xi.shape}")
    print("incarc CIC-UNSW-NB15..."); Xu, yu = load_unsw(); print(f"  {Xu.shape}")
    Xi, Xu, common = harmonize(Xi, Xu)
    print(f"\nFeatures COMUNE armonizate: {len(common)}")

    results = []
    # within-dataset (baseline) pe features comune: holdout 30%
    for name, X, y in [("IDS2017", Xi, yi), ("UNSW", Xu, yu)]:
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, stratify=y, random_state=RS)
        clf = fit_rf(Xtr, ytr); p = clf.predict(Xte)
        results.append((f"{name} -> {name} (within)", accuracy_score(yte,p), f1_score(yte,p)))
        del clf, Xtr, Xte, ytr, yte, p; gc.collect()

    # cross-dataset: train pe tot A, test pe tot B
    print("\ntrain IDS2017 -> test UNSW...")
    clf = fit_rf(Xi, yi); p = clf.predict(Xu)
    results.append(("IDS2017 -> UNSW (cross)", accuracy_score(yu,p), f1_score(yu,p)))
    print(classification_report(yu, p, target_names=["BENIGN","ATTACK"], digits=4, zero_division=0))
    del clf, p; gc.collect()

    print("\ntrain UNSW -> test IDS2017...")
    clf = fit_rf(Xu, yu); p = clf.predict(Xi)
    results.append(("UNSW -> IDS2017 (cross)", accuracy_score(yi,p), f1_score(yi,p)))
    print(classification_report(yi, p, target_names=["BENIGN","ATTACK"], digits=4, zero_division=0))

    print(f"\n{'='*55}\nSUMAR DOMAIN SHIFT (binary, {len(common)} features comune)\n{'='*55}")
    print(f"{'experiment':32} {'accuracy':>9} {'F1(attack)':>11}")
    for r in results: print(f"{r[0]:32} {r[1]:>9.4f} {r[2]:>11.4f}")

if __name__ == "__main__":
    main()
