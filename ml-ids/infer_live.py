#!/usr/bin/env python3
"""
infer_live.py — serviciu de inferenta ML LIVE: scoreaza flow-uri Suricata din ES cu
rf_cluster.joblib si scrie predictiile in index PARALEL security-ml-* (NU atinge security-*).

Self-consistent cu antrenarea (fara domain shift): reutilizeaza EXACT feature-extract-ul din
collect_cluster_data.py (import direct, fara duplicare) si aliniaza coloanele la schema
modelului (clf.feature_names_in_) prin reindex — coloanele one-hot lipsa devin 0, cele
nevazute la antrenare se ignora. Asa modelul primeste exact aceleasi features ca la fit.

Read-only pe pipeline-ul existent (doar interogheaza security-*); scrie doar in security-ml-*.

Doua moduri:
  # one-shot pe o fereastra (demo / backfill peste un scenariu deja rulat):
  ./.venv/bin/python infer_live.py --since now-30m --until now
  # continuu (pipeline "live"), poll la fiecare 30s, upsert pe flow_id (fara duplicate):
  ./.venv/bin/python infer_live.py --watch --interval 30
"""
import argparse, json, time, os, urllib.request
import pandas as pd, joblib
import collect_cluster_data as ccd                            # reutilizam feature-extract-ul validat
from collect_cluster_data import FIELDS, to_row              # helpers ES-independenti

# ES_URL configurabil: implicit floating IP (rulare pe laptop, ca acum); override din env
# pentru rulare in-cluster ca Deployment (ex: ES_URL=http://10.11.0.3:9200, IP intern node-4).
ES = os.environ.get("ES_URL", ccd.ES)
ccd.ES = ES                                                   # es_post (scroll/alert_flow_ids) citeste ccd.ES
es_post = ccd.es_post

HERE  = os.path.dirname(os.path.abspath(__file__))
MODEL = os.path.join(HERE, "models", "rf_cluster.joblib")
DROP  = ["flow_id", "node", "scenario", "label"]      # non-features (la fel ca train_cluster_rf.py)
CATEG = ["proto", "app_proto", "flow_state"]          # nominale -> one-hot (idem)
SRC   = FIELDS + ["@timestamp"]                        # +timestamp pt doc-ul de output

def scroll(query, source):
    r = es_post("/security-*/_search?scroll=2m",
                {"size": 1000, "query": query, "_source": source, "sort": ["_doc"]})
    sid = r.get("_scroll_id"); hits = r["hits"]["hits"]
    while hits:
        for h in hits: yield h["_source"]
        r = es_post("/_search/scroll", {"scroll": "2m", "scroll_id": sid})
        sid = r.get("_scroll_id"); hits = r["hits"]["hits"]

def alert_flow_ids(since, until):
    """Set de flow_id pe care a tras o semnatura Suricata in fereastra (pt corelare determinist<->ML)."""
    q = {"bool": {"must": [
        {"term": {"log_type.keyword": "suricata"}},
        {"term": {"event_type.keyword": "alert"}},
        {"range": {"@timestamp": {"gte": since, "lte": until}}}]}}
    ids = set()
    for s in scroll(q, ["flow_id"]):
        if s.get("flow_id") is not None: ids.add(str(s.get("flow_id")))
    return ids

def es_bulk(lines):
    if not lines: return
    data = ("\n".join(lines) + "\n").encode()
    req = urllib.request.Request(ES + "/_bulk", data=data,
            headers={"Content-Type": "application/x-ndjson",
                     "User-Agent": "ml-ids-infer/1.0"}, method="POST")   # evita ET INFO Python-urllib
    resp = json.loads(urllib.request.urlopen(req, timeout=120).read())
    if resp.get("errors"):
        for it in resp["items"]:
            err = list(it.values())[0].get("error")
            if err: print("  bulk error:", err); break

def idx_for(ts):  # security-ml-YYYY.MM.dd, oglindeste security-YYYY.MM.dd
    return "security-ml-" + (ts[:10].replace("-", ".") if ts else time.strftime("%Y.%m.%d"))

def run_window(clf, feat_cols, since, until, threshold, alert_since=None):
    q = {"bool": {"must": [
        {"term": {"log_type.keyword": "suricata"}},
        {"term": {"event_type.keyword": "flow"}},
        {"range": {"@timestamp": {"gte": since, "lte": until}}}]}}
    raw, rows = [], []
    for s in scroll(q, SRC):
        raw.append(s); rows.append(to_row(s, "", ""))      # label/scenario goale -> oricum in DROP
    if not rows:
        print(f"[{since}..{until}] 0 flow-uri"); return 0
    # Corelare alerte pe fereastra (potential) MAI LARGA decat scorarea flow-urilor. In watch,
    # fereastra de flow e ingusta (now-45s), dar alerta Suricata pt acelasi flow_id e emisa de obicei
    # INAINTE de flow event (la match-ul semnaturii), deci poate cadea in afara ferestrei de 45s -> ratata
    # (=> totul iese fals 'ml_only'). alert_since (ex now-5m) prinde alertele aterizate mai devreme,
    # facand corelarea both/ml_only corecta si live, nu doar la backfill. Vezi k8s/README.md.
    alert_ids = alert_flow_ids(alert_since or since, until)  # corelare: ce flow-uri au tras o regula Suricata
    X = pd.DataFrame(rows).drop(columns=[c for c in DROP if c in rows[0]])
    X = pd.get_dummies(X, columns=[c for c in CATEG if c in X.columns], dummy_na=False)
    X = X.reindex(columns=feat_cols, fill_value=0).fillna(0)  # ALINIERE la schema modelului
    j = list(clf.classes_).index(1)
    proba = clf.predict_proba(X)[:, j]
    lines = []
    for s, p in zip(raw, proba):
        ts = s.get("@timestamp")
        is_attack = bool(p >= threshold)
        ruled = str(s.get("flow_id")) in alert_ids
        det = ("both" if is_attack and ruled else "ml_only" if is_attack else
               "rule_only" if ruled else "quiet")          # cele 4 celule determinist<->ML
        doc = {"@timestamp": ts, "flow_id": s.get("flow_id"), "node": s.get("node"),
               "src_ip": s.get("src_ip"), "dest_ip": s.get("dest_ip"),
               "src_port": s.get("src_port"), "dest_port": s.get("dest_port"),
               "proto": s.get("proto"), "app_proto": s.get("app_proto"),
               "ml_score": round(float(p), 4),
               "ml_label": "ATTACK" if is_attack else "BENIGN",
               "rule_alerted": ruled, "detection": det,
               "model": "rf_cluster"}
        # _id = flow_id => re-scorarea aceluiasi flux face UPSERT (fara duplicate in watch mode)
        lines.append(json.dumps({"index": {"_index": idx_for(ts), "_id": str(s.get("flow_id"))}}))
        lines.append(json.dumps(doc))
    es_bulk(lines)
    n_att = int((proba >= threshold).sum())
    print(f"[{since}..{until}] scorate {len(rows)} flow-uri -> {n_att} ATTACK / {len(rows) - n_att} BENIGN")
    return len(rows)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", default="now-15m")
    ap.add_argument("--until", default="now")
    ap.add_argument("--watch", action="store_true", help="poll continuu (fereastra glisanta)")
    ap.add_argument("--interval", type=int, default=30, help="secunde intre poll-uri (watch)")
    ap.add_argument("--threshold", type=float, default=0.5, help="prag prob. ATTACK")
    ap.add_argument("--alert-window", default="5m",
                    help="lookback corelare alerte Suricata in watch (decuplat de fereastra de flow)")
    a = ap.parse_args()

    clf = joblib.load(MODEL); feat_cols = list(clf.feature_names_in_)
    print(f"model: {MODEL} | {len(feat_cols)} features | threshold {a.threshold}")
    if not a.watch:
        run_window(clf, feat_cols, a.since, a.until, a.threshold); return
    print(f"watch: poll la {a.interval}s | corelare alerte pe now-{a.alert_window} (Ctrl-C pt stop)")
    while True:
        run_window(clf, feat_cols, f"now-{a.interval + 15}s", "now", a.threshold,
                   alert_since=f"now-{a.alert_window}")
        time.sleep(a.interval)

if __name__ == "__main__":
    main()
