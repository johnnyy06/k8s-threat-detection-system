#!/usr/bin/env python3
"""
train_rf.py — Random Forest IDS classifier pe dataset-uri CIC (flow-based, CICFlowMeter).
Componenta ML exploratorie a proiectului (reducere FP / detectie network). Vezi DATASETS.md.

Rulare (din ml-ids/, cu venv activat):
    ./.venv/bin/python train_rf.py cicids2017
    ./.venv/bin/python train_rf.py cicunsw
Output: metrici in stdout + ploturi (confusion matrix, feature importance) + model in reports/ & models/.
"""
import sys, glob, os, time, json, gc
import numpy as np, pandas as pd
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (classification_report, confusion_matrix,
                             roc_auc_score, ConfusionMatrixDisplay)
import joblib

HERE = os.path.dirname(os.path.abspath(__file__))
os.makedirs(f"{HERE}/reports", exist_ok=True)
os.makedirs(f"{HERE}/models", exist_ok=True)
RANDOM_STATE = 42

UNSW_LABELS = {0:"Benign",1:"Analysis",2:"Backdoor",3:"DoS",4:"Exploits",
               5:"Fuzzers",6:"Generic",7:"Reconnaissance",8:"Shellcode",9:"Worms"}

def clean_numeric(df):
    """Inf->NaN, dropna pe randuri (problema cunoscuta CIC-IDS2017), apoi downcast float64->float32
    pentru a injumatati amprenta de memorie (evita OOM-ul WSL pe 2.83M randuri)."""
    df = df.replace([np.inf, -np.inf], np.nan)
    before = len(df)
    df = df.dropna()
    print(f"  cleanup: dropped {before-len(df):,} randuri cu NaN/Inf -> {len(df):,} ramase")
    for c in df.select_dtypes(include=["float64"]).columns:
        df[c] = df[c].astype("float32")
    for c in df.select_dtypes(include=["int64"]).columns:
        df[c] = pd.to_numeric(df[c], downcast="integer")
    return df

def load_cicids2017():
    files = sorted(glob.glob(f"{HERE}/CIC-IDS2017/MachineLearningCSV/*.csv"))
    print(f"[CIC-IDS2017] incarc {len(files)} fisiere...")
    parts = []
    for f in files:
        d = pd.read_csv(f, low_memory=False, encoding="latin-1")
        d.columns = [c.strip() for c in d.columns]
        parts.append(d)
    df = pd.concat(parts, ignore_index=True)
    df.columns = [c.strip() for c in df.columns]
    y_multi = df["Label"].astype(str).str.strip()
    # Fix mojibake: CIC-IDS2017 are un en-dash cp1252 (0x96) in "Web Attack <96> X" -> normalizez la " - "
    y_multi = y_multi.str.replace(r"\s*[^\x00-\x7F]+\s*", " - ", regex=True).str.strip()
    X = df.drop(columns=["Label"]).select_dtypes(include=[np.number])
    Xy = pd.concat([X, y_multi.rename("Label")], axis=1)
    Xy = clean_numeric(Xy)
    y_multi = Xy["Label"]; X = Xy.drop(columns=["Label"])
    y_bin = (y_multi != "BENIGN").astype(int)   # 1 = ATTACK, 0 = BENIGN
    return X, y_bin, y_multi

def load_cicunsw():
    print("[CIC-UNSW-NB15] incarc Data.csv + Label.csv...")
    X = pd.read_csv(f"{HERE}/CIC-UNSW-NB15/Data.csv", low_memory=False)
    X.columns = [c.strip() for c in X.columns]
    y_num = pd.read_csv(f"{HERE}/CIC-UNSW-NB15/Label.csv")["Label"]
    X = X.select_dtypes(include=[np.number]).reset_index(drop=True)
    y_num = y_num.reset_index(drop=True)
    Xy = pd.concat([X, y_num.rename("Label")], axis=1)
    Xy = clean_numeric(Xy)
    y_num = Xy["Label"].astype(int); X = Xy.drop(columns=["Label"])
    y_multi = y_num.map(UNSW_LABELS)
    y_bin = (y_num != 0).astype(int)             # 1 = ATTACK, 0 = Benign
    return X, y_bin, y_multi

def evaluate(name, mode, X, y):
    print(f"\n{'='*70}\n{name} — {mode}\n{'='*70}")
    print("distributie clase:", dict(pd.Series(y).value_counts()))
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.30, stratify=y,
                                           random_state=RANDOM_STATE)
    clf = RandomForestClassifier(n_estimators=100, n_jobs=-1,
                                 class_weight="balanced", random_state=RANDOM_STATE)
    t=time.time(); clf.fit(Xtr, ytr); print(f"  train: {time.time()-t:.1f}s pe {len(Xtr):,} randuri")
    ypred = clf.predict(Xte)
    print(classification_report(yte, ypred, digits=4, zero_division=0))
    if mode == "binary":
        try:
            auc = roc_auc_score(yte, clf.predict_proba(Xte)[:,1])
            print(f"  ROC-AUC: {auc:.4f}")
        except Exception as e: print("  ROC-AUC n/a:", e)
    # confusion matrix plot
    fig, ax = plt.subplots(figsize=(8,7))
    ConfusionMatrixDisplay.from_predictions(yte, ypred, ax=ax, xticks_rotation=45,
                                            normalize="true", values_format=".2f")
    ax.set_title(f"{name} — {mode} (normalized)")
    plt.tight_layout(); cm_path=f"{HERE}/reports/cm_{name}_{mode}.png"; plt.savefig(cm_path, dpi=120); plt.close()
    # feature importance (top 15)
    fi = pd.Series(clf.feature_importances_, index=X.columns).sort_values(ascending=False).head(15)
    fig, ax = plt.subplots(figsize=(9,6)); fi[::-1].plot.barh(ax=ax)
    ax.set_title(f"{name} — top 15 feature importance ({mode})")
    plt.tight_layout(); fi_path=f"{HERE}/reports/fi_{name}_{mode}.png"; plt.savefig(fi_path, dpi=120); plt.close()
    joblib.dump(clf, f"{HERE}/models/rf_{name}_{mode}.joblib")
    print(f"  saved: {cm_path}, {fi_path}, models/rf_{name}_{mode}.joblib")
    del clf, Xtr, Xte, ytr, yte, ypred; gc.collect()   # elibereaza memoria intre rulari (anti-OOM)

def main():
    # arg1 = dataset (cicids2017|cicunsw), arg2 = mode (binary|multiclass|both, default both)
    which = sys.argv[1] if len(sys.argv)>1 else "cicids2017"
    mode  = sys.argv[2] if len(sys.argv)>2 else "both"
    if which == "cicids2017":
        X, yb, ym = load_cicids2017(); name="CIC-IDS2017"
    elif which == "cicunsw":
        X, yb, ym = load_cicunsw(); name="CIC-UNSW-NB15"
    else:
        print("arg: cicids2017 | cicunsw [binary|multiclass|both]"); sys.exit(1)
    mem = X.memory_usage(deep=True).sum()/1e6
    print(f"\n{name}: X shape {X.shape}, {X.shape[1]} features, ~{mem:.0f} MB in RAM (float32)")
    if mode in ("binary","both"):
        evaluate(name, "binary", X, yb)
    if mode in ("multiclass","both"):
        evaluate(name, "multiclass", X, ym)

if __name__ == "__main__":
    main()
