#!/usr/bin/env python3
"""
study_det_vs_ml.py — studiu comparativ DETERMINIST (semnaturi Suricata) vs ML (RandomForest)
pe flow-uri Suricata, cu ground truth din atacuri controlate (runs.json scris de run_batch.sh).

Apples-to-apples: ambii detectori pe ACELEASI flow-uri (network-flow scope). Falco (host) =
complementar, NU in comparatia cantitativa.
  - detector DETERMINIST: flow = ATAC daca a tras o semnatura Suricata (rule_alerted=true)
  - detector ML:          flow = ATAC daca ml_label=ATTACK
Ground truth: ATTACK = flow cu attacker IP in fereastra scenariului; BENIGN = fereastra liniste.

Iesire: study/REPORT.md (tabele) + study/results.csv (per-flux) + grafice in study/reports/.
Rulare:  ./.venv/bin/python study/study_det_vs_ml.py   (din ml-ids/)
"""
import os, sys, json, csv, subprocess, urllib.request
import numpy as np
import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support, accuracy_score

ES   = os.environ.get("ES_URL", "http://10.102.14.31:9200")
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)                     # ml-ids/
RUNS = os.path.join(HERE, "runs.json")
RPT  = os.path.join(HERE, "reports"); os.makedirs(RPT, exist_ok=True)
SRC  = ["ml_label", "rule_alerted", "flow_id", "src_ip", "dest_ip", "@timestamp"]

def es_post(path, body):
    req = urllib.request.Request(ES+path, data=json.dumps(body).encode(),
            headers={"Content-Type":"application/json","User-Agent":"ml-ids-study/1.0"}, method="POST")
    return json.loads(urllib.request.urlopen(req, timeout=60).read())

def scroll(query):
    r = es_post("/security-ml-*/_search?scroll=2m", {"size":1000,"query":query,"_source":SRC,"sort":["_doc"]})
    sid=r.get("_scroll_id"); hits=r["hits"]["hits"]
    while hits:
        for h in hits: yield h["_source"]
        r = es_post("/_search/scroll", {"scroll":"2m","scroll_id":sid}); sid=r.get("_scroll_id"); hits=r["hits"]["hits"]

def fetch(start, end, attacker=None):
    must=[{"range":{"@timestamp":{"gte":start,"lte":end}}}]
    if attacker:
        must.append({"bool":{"should":[{"term":{"src_ip":attacker}},{"term":{"dest_ip":attacker}}],
                             "minimum_should_match":1}})
    return list(scroll({"bool":{"must":must}}))

def to_rec(s, truth, scen):
    return {"flow_id":str(s.get("flow_id")), "scenario":scen, "truth":truth,
            "ml":1 if s.get("ml_label")=="ATTACK" else 0,
            "det":1 if s.get("rule_alerted") else 0}

def metrics(recs):
    if not recs: return None
    y=np.array([r["truth"] for r in recs]);
    out={}
    for k in ("det","ml"):
        p=np.array([r[k] for r in recs])
        pr,rc,f1,_=precision_recall_fscore_support(y,p,average="binary",zero_division=0,pos_label=1)
        out[k]={"precision":pr,"recall":rc,"f1":f1,"acc":accuracy_score(y,p),
                "cm":confusion_matrix(y,p,labels=[0,1]).tolist()}
    return out

def fmt(m): return f"P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f} acc={m['acc']:.3f}"

def main():
    runs=json.load(open(RUNS))
    bl=runs["baseline"]; scenarios=runs["scenarios"]
    win_start=bl["start"]

    # 1) Scorare consistenta a INTREGII ferestre (one-shot infer: aliniaza ml_label + rule_alerted cu
    #    corelare pe fereastra larga). Pod-ul live scoreaza si el, dar one-shot garanteaza completitudine.
    print("[1] scorez fereastra studiului (infer_live one-shot)...")
    subprocess.run([os.path.join(ROOT,".venv/bin/python"), os.path.join(ROOT,"infer_live.py"),
                    "--since", win_start, "--until", "now"], check=False)

    # 2) Colectare + etichetare
    print("[2] colectez + etichetez flow-uri din security-ml-*...")
    benign=[to_rec(s,0,"baseline") for s in fetch(bl["start"], bl["end"])]
    # dedup benign pe flow_id
    seen=set(); benign=[r for r in benign if not (r["flow_id"] in seen or seen.add(r["flow_id"]))]
    from datetime import datetime, timedelta
    def add_secs(iso,secs):
        return (datetime.strptime(iso,"%Y-%m-%dT%H:%M:%SZ")+timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%SZ")
    BUFFER_S=180   # lag flow-end Suricata: flow events emise DUPA inchiderea conexiunii -> extinde fereastra
    per_scen={}
    for idx,sc in enumerate(scenarios):
        if not sc.get("attacker_ip"):
            print(f"  ! {sc['id']}: lipsa attacker_ip, sar"); continue
        coll_end=add_secs(sc["end"],BUFFER_S)
        for nx in scenarios[idx+1:]:        # cap la urmatorul scenariu cu ACELASI attacker (evita overlap)
            if nx.get("attacker_ip")==sc["attacker_ip"]: coll_end=min(coll_end,nx["start"]); break
        atk=[to_rec(s,1,sc["id"]) for s in fetch(sc["start"], coll_end, sc["attacker_ip"])]
        s2=set(); atk=[r for r in atk if not (r["flow_id"] in s2 or s2.add(r["flow_id"]))]
        per_scen[sc["id"]]=atk
        print(f"  {sc['id']} ({sc['name']}, attacker {sc['attacker_ip']}): {len(atk)} flow-uri ATTACK")

    # agregat cu dedup global pe flow_id; scoate din BENIGN orice flux care apare ca ATTACK
    gseen=set(); all_atk=[r for v in per_scen.values() for r in v if not (r["flow_id"] in gseen or gseen.add(r["flow_id"]))]
    benign=[r for r in benign if r["flow_id"] not in gseen]
    print(f"  baseline BENIGN: {len(benign)} flow-uri")

    # 3) Metrici per-scenariu (ATTACK-ul scenariului + acelasi BENIGN) + agregat
    lines=["# Studiu: Determinist (semnaturi Suricata) vs ML (RandomForest) — network-flow\n",
           "Apples-to-apples: ambii detectori pe ACELEASI flow-uri Suricata. Ground truth din atacuri",
           "controlate (ATTACK = attacker IP in fereastra; BENIGN = fereastra liniste, separata temporal).",
           "Falco (host/syscall) e complementar — NU intra in aceasta comparatie cantitativa.\n",
           f"Dataset: {len(all_atk)} flow-uri ATTACK (din {len(per_scen)} scenarii) + {len(benign)} BENIGN.\n",
           "## Rezultate per scenariu (vs acelasi set BENIGN)\n",
           "| Scenariu | #ATTACK | Determinist (Suricata) | ML (RandomForest) |",
           "|---|---|---|---|"]
    scen_names={sc["id"]:sc["name"] for sc in scenarios}
    rec_recall={}
    for sid,atk in per_scen.items():
        m=metrics(atk+benign)
        lines.append(f"| {sid} ({scen_names.get(sid,'')}) | {len(atk)} | {fmt(m['det'])} | {fmt(m['ml'])} |")
        rec_recall[sid]=(m['det']['recall'], m['ml']['recall'])
    # agregat
    magg=metrics(all_atk+benign)
    lines += ["\n## Agregat (toate scenariile)\n",
              "| Detector | Precision | Recall | F1 | Accuracy |", "|---|---|---|---|---|",
              f"| Determinist (Suricata) | {magg['det']['precision']:.3f} | {magg['det']['recall']:.3f} | {magg['det']['f1']:.3f} | {magg['det']['acc']:.3f} |",
              f"| ML (RandomForest) | {magg['ml']['precision']:.3f} | {magg['ml']['recall']:.3f} | {magg['ml']['f1']:.3f} | {magg['ml']['acc']:.3f} |"]

    # 4) Complementaritate pe flow-urile ATTACK (cine prinde ce)
    both=sum(1 for r in all_atk if r["det"] and r["ml"])
    ml_only=sum(1 for r in all_atk if r["ml"] and not r["det"])
    det_only=sum(1 for r in all_atk if r["det"] and not r["ml"])
    none=sum(1 for r in all_atk if not r["det"] and not r["ml"])
    n=max(len(all_atk),1)
    union_recall=(both+ml_only+det_only)/n
    lines += ["\n## Complementaritate (pe flow-urile ATTACK)\n",
              f"- **both** (ambii prind): {both} ({both/n:.1%})",
              f"- **doar ML** (ML prinde, semnaturile rateaza): {ml_only} ({ml_only/n:.1%})",
              f"- **doar determinist** (semnatura prinde, ML rateaza): {det_only} ({det_only/n:.1%})",
              f"- **niciunul** (ratat de ambii): {none} ({none/n:.1%})",
              f"- **recall uniune** (det SAU ml): **{union_recall:.3f}** — vs det {magg['det']['recall']:.3f}, ml {magg['ml']['recall']:.3f}",
              "\n> Concluzia complementaritatii: stratul combinat (semnaturi + ML) prinde mai mult decat oricare singur.",
              "\n## Caveat (onestitate metodologica)",
              "- BENIGN-ul e dominat de trafic de infra (VXLAN/calico/DNS), usor separabil -> scorurile sunt",
              "  optimiste; relevanta e COMPARATIA dintre detectori, nu valorile absolute.",
              "- Evaluare in-environment (instante noi ale tipurilor de atac antrenate); generalizarea intre",
              "  medii e tratata separat (studiul cross-dataset, RESULTS.md).",
              "- s07 (exfil egress) NU e inclus aici din cauza SNAT-ului Calico (atribuire per-pod pierduta la egress);",
              "  scenariile alese (s05 scan, s11 lateral, s09 web) au atacatorul ca sursa spre tinte interne = atribuire curata."]

    open(os.path.join(HERE,"REPORT.md"),"w").write("\n".join(lines)+"\n")
    with open(os.path.join(HERE,"results.csv"),"w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=["flow_id","scenario","truth","ml","det"]); w.writeheader()
        for r in all_atk+benign: w.writerow(r)

    # 5) Grafice
    # (a) recall per scenariu: det vs ml vs uniune
    ids=list(per_scen.keys()); x=np.arange(len(ids)); width=0.27
    det_r=[rec_recall[i][0] for i in ids]; ml_r=[rec_recall[i][1] for i in ids]
    un_r=[]
    for i in ids:
        a=per_scen[i]; nn=max(len(a),1); un_r.append(sum(1 for r in a if r["det"] or r["ml"])/nn)
    fig,ax=plt.subplots(figsize=(7,4))
    ax.bar(x-width,det_r,width,label="Determinist (Suricata)",color="#991b1b")
    ax.bar(x,ml_r,width,label="ML (RandomForest)",color="#6d28d9")
    ax.bar(x+width,un_r,width,label="Uniune (det OR ml)",color="#065f46")
    ax.set_xticks(x); ax.set_xticklabels([f"{i}\n{scen_names.get(i,'')}" for i in ids],fontsize=8)
    ax.set_ylabel("Recall (detecție atac)"); ax.set_ylim(0,1.05)
    ax.set_title("Recall per scenariu — determinist vs ML vs uniune"); ax.legend(fontsize=8)
    plt.tight_layout(); plt.savefig(os.path.join(RPT,"recall_per_scenario.png"),dpi=120); plt.close()

    # (b) confusion matrices agregate
    for k,col,title in (("det","Reds","Determinist (Suricata)"),("ml","Purples","ML (RandomForest)")):
        cm=np.array(magg[k]["cm"]); fig,ax=plt.subplots(figsize=(3.6,3.2))
        im=ax.imshow(cm,cmap=col); ax.set_xticks([0,1]); ax.set_yticks([0,1])
        ax.set_xticklabels(["BENIGN","ATTACK"]); ax.set_yticklabels(["BENIGN","ATTACK"])
        ax.set_xlabel("Prezis"); ax.set_ylabel("Real"); ax.set_title(title,fontsize=10)
        for (r,c),v in np.ndenumerate(cm): ax.text(c,r,str(v),ha="center",va="center",
            color="white" if v>cm.max()/2 else "black")
        plt.tight_layout(); plt.savefig(os.path.join(RPT,f"cm_{k}.png"),dpi=120); plt.close()

    print("\n=== AGREGAT ===")
    print("Determinist:", fmt(magg["det"])); print("ML        :", fmt(magg["ml"]))
    print(f"Complementaritate ATTACK: both {both} | doar-ML {ml_only} | doar-det {det_only} | niciunul {none}")
    print(f"Recall uniune {union_recall:.3f}")
    print(f"\nScris: REPORT.md, results.csv, reports/recall_per_scenario.png, reports/cm_*.png")

if __name__=="__main__":
    main()
