#!/usr/bin/env python3
"""
train_cluster_rf.py — Random Forest pe flow-uri Suricata ETICHETATE din PROPRIUL cluster
(cluster_flows.csv produs de collect_cluster_data.py). Features native Suricata EVE (~20),
deci model self-consistent cu pipeline-ul live (fara domain shift, fara CICFlowMeter).

Date mici + dezechilibrate => class_weight='balanced' + StratifiedKFold CV (metrici robuste)
pe langa holdout. Output: metrici + confusion matrix + feature importance in reports/.

Rulare: ./.venv/bin/python train_cluster_rf.py
"""
import os, numpy as np, pandas as pd
import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_predict
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay, f1_score
import joblib

HERE = os.path.dirname(os.path.abspath(__file__)); RS = 42
os.makedirs(f"{HERE}/reports", exist_ok=True); os.makedirs(f"{HERE}/models", exist_ok=True)

DROP = ["flow_id", "node", "scenario", "label"]          # non-features
CATEG = ["proto", "app_proto", "flow_state"]              # nominale -> one-hot

def main():
    df = pd.read_csv(f"{HERE}/cluster_flows.csv")
    print(f"dataset: {df.shape} | label: {dict(df.label.value_counts())}")
    y = (df["label"] == "ATTACK").astype(int)
    X = df.drop(columns=[c for c in DROP if c in df.columns])
    X = pd.get_dummies(X, columns=[c for c in CATEG if c in X.columns], dummy_na=False)
    X = X.fillna(0)
    print(f"features dupa encoding: {X.shape[1]}")

    clf = RandomForestClassifier(n_estimators=300, class_weight="balanced",
                                 n_jobs=-1, random_state=RS)

    # --- StratifiedKFold CV (robust pe date putine) ---
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=RS)
    ycv = cross_val_predict(clf, X, y, cv=skf, n_jobs=-1)
    print("\n=== 5-fold CV (tot datasetul) ===")
    print(classification_report(y, ycv, target_names=["BENIGN","ATTACK"], digits=4, zero_division=0))
    print("confusion matrix (CV):\n", confusion_matrix(y, ycv))

    # --- holdout 70/30 pt model final + ploturi ---
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, stratify=y, random_state=RS)
    clf.fit(Xtr, ytr); p = clf.predict(Xte)
    print("\n=== Holdout 30% ===")
    print(classification_report(yte, p, target_names=["BENIGN","ATTACK"], digits=4, zero_division=0))

    fig, ax = plt.subplots(figsize=(5,4))
    ConfusionMatrixDisplay.from_predictions(yte, p, display_labels=["BENIGN","ATTACK"], ax=ax,
                                            values_format="d", cmap="Blues")
    ax.set_title("Cluster RF (Suricata flows) — holdout"); plt.tight_layout()
    plt.savefig(f"{HERE}/reports/cm_cluster.png", dpi=120); plt.close()

    fi = pd.Series(clf.feature_importances_, index=X.columns).sort_values(ascending=False).head(15)
    fig, ax = plt.subplots(figsize=(9,6)); fi[::-1].plot.barh(ax=ax)
    ax.set_title("Cluster RF — top 15 feature importance"); plt.tight_layout()
    plt.savefig(f"{HERE}/reports/fi_cluster.png", dpi=120); plt.close()

    joblib.dump(clf, f"{HERE}/models/rf_cluster.joblib")
    print(f"\nsaved: reports/cm_cluster.png, reports/fi_cluster.png, models/rf_cluster.joblib")
    print("top features:", list(fi.index[:8]))

if __name__ == "__main__":
    main()
