#!/usr/bin/env python3
"""
collect_cluster_data.py — strange un dataset ETICHETAT de flow-uri Suricata din PROPRIUL cluster,
din Elasticsearch (index security-*, event_type=flow). Pentru antrenarea unui RF specific mediului
(fara domain shift). Features = native Suricata EVE (~20), self-consistent cu pipeline-ul live.

LABELING pe baza de ground-truth (tu controlezi atacurile):
  - mod attack: pastreaza DOAR flow-urile cu src_ip SAU dest_ip = IP-ul pod-ului atacator, in fereastra
                scenariului, etichetate ATTACK (+ numele scenariului).
  - mod benign: pastreaza TOATE flow-urile dintr-o fereastra LINISTITA (fara atacuri) = BENIGN.

Acumuleaza in cluster_flows.csv (append + dedup pe flow_id).

EXEMPLE:
  # 1) baseline benign (fereastra fara atacuri):
  ./.venv/bin/python collect_cluster_data.py --mode benign --since now-30m --until now
  # 2) dupa ce rulezi un scenariu, ia IP-ul pod-ului atacator:
  kubectl get pod attack-pod -n attack-target -o jsonpath='{.status.podIP}'
  # 3) colecteaza atacul (fereastra + IP atacator):
  ./.venv/bin/python collect_cluster_data.py --mode attack --scenario s11 --attacker-ip 10.1.x.y --since now-15m --until now

NOTA: --since/--until accepta date-math ES ('now-15m', 'now') sau ISO ('2026-06-16T21:00:00Z').
      ES evalueaza 'now' server-side (UTC) => fara probleme de clock-skew laptop.
"""
import argparse, json, csv, os, sys, urllib.request

ES = "http://10.102.14.31:9200"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cluster_flows.csv")

FIELDS = ["proto","network.transport","app_proto","flow.start","flow.end","flow.age","flow.state",
          "flow.bytes_toserver","flow.bytes_toclient","flow.pkts_toserver","flow.pkts_toclient",
          "src_port","dest_port","src_ip","dest_ip","flow_id","node",
          "tcp.syn","tcp.ack","tcp.psh","tcp.fin","tcp.rst","tcp.urg"]

CSV_COLS = ["flow_id","node","label","scenario",
            "proto","app_proto","duration_ms","flow_age",
            "bytes_toserver","bytes_toclient","total_bytes","pkts_toserver","pkts_toclient","total_pkts",
            "bytes_per_s","pkts_per_s","bytes_ratio","pkts_ratio",
            "src_port","dest_port","flow_state",
            "tcp_syn","tcp_ack","tcp_psh","tcp_fin","tcp_rst","tcp_urg"]

def es_post(path, body):
    # User-Agent explicit: altfel urllib trimite "Python-urllib/3.x" pe care Suricata il marcheaza
    # "ET INFO Python-urllib Suspicious User Agent" => zgomot recurent in security-* de la pod-ul ML.
    req = urllib.request.Request(ES+path, data=json.dumps(body).encode(),
                                 headers={"Content-Type":"application/json",
                                          "User-Agent":"ml-ids-infer/1.0"}, method="POST")
    return json.loads(urllib.request.urlopen(req, timeout=60).read())

def es_scroll(query):
    """Itereaza toate hit-urile (scroll API)."""
    r = es_post("/security-*/_search?scroll=2m", {"size":1000,"query":query,
                "_source":FIELDS, "sort":["_doc"]})
    sid = r.get("_scroll_id"); hits = r["hits"]["hits"]
    while hits:
        for h in hits: yield h["_source"]
        r = es_post("/_search/scroll", {"scroll":"2m","scroll_id":sid})
        sid = r.get("_scroll_id"); hits = r["hits"]["hits"]

def g(d, dotted, default=None):
    cur = d
    for p in dotted.split("."):
        if isinstance(cur, dict) and p in cur: cur = cur[p]
        else: return default
    return cur

def parse_ts(s):
    # '2026-06-16T21:32:06.843390+0000' -> ms epoch (best effort)
    from datetime import datetime
    try:
        s2 = s.replace("Z","+0000")
        # taie la microsecunde
        return datetime.strptime(s2[:26]+s2[-5:] if "+" in s2 else s2, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
    except Exception:
        return None

def to_row(s, label, scenario):
    bts = g(s,"flow.bytes_toserver",0) or 0; btc = g(s,"flow.bytes_toclient",0) or 0
    pts = g(s,"flow.pkts_toserver",0) or 0; ptc = g(s,"flow.pkts_toclient",0) or 0
    st = parse_ts(g(s,"flow.start","") or ""); en = parse_ts(g(s,"flow.end","") or "")
    dur = max((en-st), 0.0) if (st and en) else 0.0
    dur_ms = round(dur*1000, 3)
    tb = bts+btc; tp = pts+ptc
    eps = max(dur, 0.001)
    def b(x): return 1 if g(s,x) else 0
    return {
        "flow_id": s.get("flow_id"), "node": s.get("node"), "label": label, "scenario": scenario or "",
        "proto": g(s,"proto") or g(s,"network.transport") or "", "app_proto": s.get("app_proto") or "",
        "duration_ms": dur_ms, "flow_age": g(s,"flow.age",0),
        "bytes_toserver": bts, "bytes_toclient": btc, "total_bytes": tb,
        "pkts_toserver": pts, "pkts_toclient": ptc, "total_pkts": tp,
        "bytes_per_s": round(tb/eps,3), "pkts_per_s": round(tp/eps,3),
        "bytes_ratio": round(bts/max(btc,1),4), "pkts_ratio": round(pts/max(ptc,1),4),
        "src_port": s.get("src_port") or 0, "dest_port": s.get("dest_port") or 0,
        "flow_state": g(s,"flow.state") or "",
        "tcp_syn": b("tcp.syn"), "tcp_ack": b("tcp.ack"), "tcp_psh": b("tcp.psh"),
        "tcp_fin": b("tcp.fin"), "tcp_rst": b("tcp.rst"), "tcp_urg": b("tcp.urg"),
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["benign","attack"], required=True)
    ap.add_argument("--scenario", default="")
    ap.add_argument("--attacker-ip", default="")
    ap.add_argument("--since", default="now-15m")
    ap.add_argument("--until", default="now")
    a = ap.parse_args()

    must = [{"term":{"log_type.keyword":"suricata"}},
            {"term":{"event_type.keyword":"flow"}},
            {"range":{"@timestamp":{"gte":a.since,"lte":a.until}}}]
    q = {"bool":{"must":must}}
    if a.mode == "attack":
        if not a.attacker_ip: sys.exit("--attacker-ip e obligatoriu in mod attack")
        q["bool"]["must"].append({"bool":{"should":[
            {"term":{"src_ip":a.attacker_ip}},{"term":{"dest_ip":a.attacker_ip}}],
            "minimum_should_match":1}})
    label = "ATTACK" if a.mode=="attack" else "BENIGN"

    # dedup pe flow_id fata de ce e deja in CSV
    seen = set()
    exists = os.path.exists(OUT)
    if exists:
        with open(OUT) as f:
            for row in csv.DictReader(f): seen.add(row["flow_id"])

    n=0; dup=0
    with open(OUT, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLS)
        if not exists: w.writeheader()
        for s in es_scroll(q):
            fid = str(s.get("flow_id"))
            if fid in seen: dup+=1; continue
            seen.add(fid); w.writerow(to_row(s,label,a.scenario)); n+=1
    print(f"[{a.mode}{('/'+a.scenario) if a.scenario else ''}] adaugate {n} flow-uri ({dup} duplicate sarite) -> {OUT}")
    print(f"   fereastra: {a.since}..{a.until}" + (f" | attacker-ip {a.attacker_ip}" if a.mode=='attack' else ""))

if __name__ == "__main__":
    main()
