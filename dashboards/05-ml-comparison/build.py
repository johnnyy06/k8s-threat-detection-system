#!/usr/bin/env python3
"""
Construieste Dashboard "ML vs Deterministic Detection" — compara stratul ML
(RandomForest pe flow-uri Suricata, index security-ml-*) cu detectia determinista
(semnaturi Suricata din security-*), corelate pe `flow_id`.

Narativ central (Cap E — perspective ML):
  - Pipeline-ul ML (ml-ids/infer_live.py) scoreaza fiecare flow Suricata live cu
    rf_cluster.joblib si scrie predictia in index PARALEL security-ml-*.
  - Fiecare doc e deja imbogatit cu `detection` (corelare pe flow_id la scorare):
      both      = ML ATTACK + a tras o semnatura Suricata        (acord)
      ml_only   = ML ATTACK, nicio semnatura Suricata            (candidat detectie noua/anomalie)
      rule_only = semnatura Suricata, ML BENIGN                  (ML miss / semnatura pe flux benign)
      quiet     = ambele tacute                                  (trafic normal)
  - Astfel dashboard-ul e SINGLE-INDEX (Kibana nu face JOIN usor intre indici).

Limitare onesta (de mentionat in lucrare): comparatia e pe flow-urile SCORATE
(event_type=flow). O alerta Suricata fara un flow event scorat in fereastra nu apare.

8 panels:
  1. KPI Total flow-uri scorate
  2. KPI ML ATTACK
  3. KPI cu semnatura Suricata (rule_alerted=true)
  4. KPI Acord (both)
  5. Detection breakdown (cele 4 celule) — KEY panel
  6. Detection over time (stacked area)
  7. Top dest_port pentru ml_only (candidati detectie noua)
  8. Saved search: fluxurile ml_only (cele mai interesante pt investigatie)
"""

import json
import sys
import urllib.request
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from _config import KIBANA_URL  # noqa: E402

DASHBOARD_ID = "thesis-ml-vs-deterministic"
ML_DV_ID = "thesis-ml-security-ml"          # data view dedicat security-ml-*
ML_DV_PATTERN = "security-ml-*"
NDJSON_OUT = Path(__file__).parent / "dashboard.ndjson"
HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json"}


def api(method, path, body=None):
    req = urllib.request.Request(
        KIBANA_URL + path, method=method, headers=HEADERS,
        data=json.dumps(body).encode() if body is not None else None,
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        sys.stderr.write(f"HTTP {e.code} on {method} {path}\n{e.read().decode()[:600]}\n")
        raise


def ensure_ml_data_view():
    """Data view security-ml-* (id fix ML_DV_ID), time field @timestamp. Idempotent."""
    body = {"data_view": {"id": ML_DV_ID, "title": ML_DV_PATTERN,
                          "name": "security-ml", "timeFieldName": "@timestamp"},
            "override": True}
    try:
        r = api("POST", "/api/data_views/data_view", body)
        print(f"  [data view] security-ml created/updated (id={r['data_view']['id']})")
    except urllib.error.HTTPError as e:
        if e.code == 409:
            api("POST", f"/api/data_views/data_view/{ML_DV_ID}",
                {"data_view": {"title": ML_DV_PATTERN, "timeFieldName": "@timestamp"},
                 "refresh_fields": True})
            print("  [data view] security-ml pattern refreshed")
        else:
            raise


# ----------------------------------------------------------------------------- Lens column builders
def lens_ref(layer_id):
    return {"type": "index-pattern", "id": ML_DV_ID,
            "name": f"indexpattern-datasource-layer-{layer_id}"}


def count_col(label="Count of records", custom=False):
    out = {"label": label, "dataType": "number", "operationType": "count",
           "isBucketed": False, "scale": "ratio", "sourceField": "___records___"}
    if custom:
        out["customLabel"] = True
    return out


def terms_col(field, label, size=10, data_type="string", order_by="col-count", order_dir="desc"):
    return {"label": label, "dataType": data_type, "operationType": "terms",
            "isBucketed": True, "scale": "ordinal", "sourceField": field,
            "params": {"size": size, "orderBy": {"type": "column", "columnId": order_by},
                       "orderDirection": order_dir, "otherBucket": False,
                       "missingBucket": False, "parentFormat": {"id": "terms"}}}


def date_hist_col(interval="auto"):
    return {"label": "@timestamp", "dataType": "date", "operationType": "date_histogram",
            "isBucketed": True, "scale": "interval", "sourceField": "@timestamp",
            "params": {"interval": interval, "includeEmptyRows": True, "dropPartials": False}}


# ----------------------------------------------------------------------------- panel builders
def make_metric(panel_id, title, query="", color=None):
    body = {"attributes": {
        "title": title, "description": "", "visualizationType": "lnsMetric",
        "state": {
            "visualization": {"layerId": "lay1", "layerType": "data", "metricAccessor": "col-count",
                              **({"color": color} if color else {})},
            "query": {"query": query, "language": "kuery"}, "filters": [],
            "datasourceStates": {"formBased": {"layers": {"lay1": {
                "columnOrder": ["col-count"], "columns": {"col-count": count_col(" ", custom=True)},
                "indexPatternId": ML_DV_ID}}}, "textBased": {"layers": {}}}}},
        "references": [lens_ref("lay1")]}
    return api("POST", f"/api/saved_objects/lens/{panel_id}?overwrite=true", body)


def make_terms_bar(panel_id, title, field, query="", size=10, label="Top values", data_type="string"):
    body = {"attributes": {
        "title": title, "description": "", "visualizationType": "lnsXY",
        "state": {
            "visualization": {"legend": {"isVisible": False, "position": "right"},
                "valueLabels": "show", "preferredSeriesType": "bar_horizontal",
                "layers": [{"layerId": "lay1", "layerType": "data", "accessors": ["col-count"],
                            "position": "top", "seriesType": "bar_horizontal",
                            "showGridlines": False, "xAccessor": "col-terms"}],
                "axisTitlesVisibilitySettings": {"x": False, "yLeft": False, "yRight": False},
                "tickLabelsVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
                "labelsOrientation": {"x": 0, "yLeft": 0, "yRight": 0},
                "gridlinesVisibilitySettings": {"x": True, "yLeft": False, "yRight": False}},
            "query": {"query": query, "language": "kuery"}, "filters": [],
            "datasourceStates": {"formBased": {"layers": {"lay1": {
                "columnOrder": ["col-terms", "col-count"],
                "columns": {"col-terms": terms_col(field, label, size=size, data_type=data_type),
                            "col-count": count_col()},
                "indexPatternId": ML_DV_ID}}}, "textBased": {"layers": {}}}}},
        "references": [lens_ref("lay1")]}
    return api("POST", f"/api/saved_objects/lens/{panel_id}?overwrite=true", body)


def make_stacked_area(panel_id, title, split_by, query="", split_size=5):
    body = {"attributes": {
        "title": title, "description": "", "visualizationType": "lnsXY",
        "state": {
            "visualization": {"legend": {"isVisible": True, "position": "right"},
                "valueLabels": "hide", "fittingFunction": "None",
                "preferredSeriesType": "area_stacked",
                "layers": [{"layerId": "lay1", "layerType": "data", "accessors": ["col-count"],
                            "position": "top", "seriesType": "area_stacked", "showGridlines": False,
                            "xAccessor": "col-time", "splitAccessor": "col-split"}],
                "axisTitlesVisibilitySettings": {"x": False, "yLeft": False, "yRight": False},
                "tickLabelsVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
                "labelsOrientation": {"x": 0, "yLeft": 0, "yRight": 0},
                "gridlinesVisibilitySettings": {"x": True, "yLeft": True, "yRight": True}},
            "query": {"query": query, "language": "kuery"}, "filters": [],
            "datasourceStates": {"formBased": {"layers": {"lay1": {
                "columnOrder": ["col-time", "col-split", "col-count"],
                "columns": {"col-time": date_hist_col(),
                            "col-split": terms_col(split_by, split_by, size=split_size),
                            "col-count": count_col()},
                "indexPatternId": ML_DV_ID}}}, "textBased": {"layers": {}}}}},
        "references": [lens_ref("lay1")]}
    return api("POST", f"/api/saved_objects/lens/{panel_id}?overwrite=true", body)


def make_saved_search(search_id, title, columns, query="", sort_field="ml_score", sort_dir="desc"):
    search_source = {"query": {"query": query, "language": "kuery"}, "filter": [],
                     "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"}
    body = {"attributes": {
        "title": title, "description": "", "columns": columns,
        "sort": [[sort_field, sort_dir]], "rowHeight": 1, "rowsPerPage": 100,
        "isTextBasedQuery": False,
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(search_source)}},
        "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                        "type": "index-pattern", "id": ML_DV_ID}]}
    return api("POST", f"/api/saved_objects/search/{search_id}?overwrite=true", body)


# ----------------------------------------------------------------------------- layout (48-col grid)
PANELS = [
    ("kpi-total", "metric", "lens",
        {"title": "Flow-uri scorate (total)", "query": ""}, 12, 6, 0, 0),
    ("kpi-mlattack", "metric", "lens",
        {"title": "ML ATTACK", "query": "ml_label : \"ATTACK\""}, 12, 6, 12, 0),
    ("kpi-ruled", "metric", "lens",
        {"title": "Cu semnatura Suricata", "query": "rule_alerted : true"}, 12, 6, 24, 0),
    ("kpi-both", "metric", "lens",
        {"title": "Acord (both)", "query": "detection : \"both\""}, 12, 6, 36, 0),

    ("detection-breakdown", "terms_bar", "lens",
        {"title": "Comparatie determinist <-> ML (both / ml_only / rule_only / quiet)",
         "field": "detection", "size": 4, "label": "detection"}, 24, 14, 0, 6),
    ("detection-time", "stacked_area", "lens",
        {"title": "Detectie in timp (pe categorie de comparatie)",
         "split_by": "detection", "split_size": 4}, 24, 14, 24, 6),

    ("mlonly-ports", "terms_bar", "lens",
        {"title": "ml_only — top dest_port (candidati detectie noua, ratati de semnaturi)",
         "field": "dest_port", "query": "detection : \"ml_only\"", "size": 12,
         "label": "dest_port", "data_type": "number"}, 24, 14, 0, 20),
    ("attack-dests", "terms_bar", "lens",
        {"title": "ML ATTACK — top dest_ip",
         "field": "dest_ip", "query": "ml_label : \"ATTACK\"", "size": 12,
         "label": "dest_ip"}, 24, 14, 24, 20),

    ("mlonly-stream", "saved_search", "search",
        {"title": "Fluxuri ml_only (ML ATTACK fara semnatura) — pt investigatie",
         "columns": ["@timestamp", "src_ip", "dest_ip", "dest_port", "proto",
                     "app_proto", "ml_score", "node"],
         "query": "detection : \"ml_only\""}, 48, 22, 0, 34),
]


def build_panel(kind, panel_id, args):
    return {"metric": make_metric, "terms_bar": make_terms_bar,
            "stacked_area": make_stacked_area, "saved_search": make_saved_search}[kind](panel_id, **args)


def build_dashboard():
    panels_meta, references = [], []
    for i, (suffix, kind, obj_type, args, w, h, x, y) in enumerate(PANELS):
        panel_id = f"thesis-ml-{suffix}"
        print(f"  [{i+1:2d}/{len(PANELS)}] {kind:13s} -> {panel_id}")
        build_panel(kind, panel_id, args)
        ref_name = f"panel_{i}"
        panels_meta.append({"version": "8.19.10", "type": obj_type,
            "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)},
            "panelIndex": str(i), "embeddableConfig": {"enhancements": {}},
            "panelRefName": ref_name, "title": args.get("title", "panel")})
        references.append({"name": ref_name, "type": obj_type, "id": panel_id})

    dashboard_body = {"attributes": {
        "title": "ML vs Deterministic Detection",
        "description": ("Cap E — strat ML exploratoriu. Compara predictiile RandomForest "
                        "(pe flow-uri Suricata, index paralel security-ml-*) cu detectia "
                        "determinista (semnaturi Suricata), corelate pe flow_id. Celule: "
                        "both (acord) / ml_only (candidat detectie noua) / rule_only (ML miss) / "
                        "quiet. Modelul rf_cluster e antrenat pe datele PROPRII ale clusterului "
                        "(features native EVE, fara domain shift)."),
        "panelsJSON": json.dumps(panels_meta),
        "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "syncCursor": True,
                                   "syncTooltips": False, "hidePanelTitles": False}),
        "version": 1, "timeRestore": True, "timeTo": "now", "timeFrom": "now-24h",
        "refreshInterval": {"pause": True, "value": 30000},
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
            {"query": {"query": "", "language": "kuery"}, "filter": []})}},
        "references": references}
    print(f"  [dashboard] {DASHBOARD_ID}")
    api("POST", f"/api/saved_objects/dashboard/{DASHBOARD_ID}?overwrite=true", dashboard_body)


def export_ndjson():
    body = {"objects": [{"type": "dashboard", "id": DASHBOARD_ID}], "includeReferencesDeep": True}
    req = urllib.request.Request(KIBANA_URL + "/api/saved_objects/_export",
        method="POST", headers=HEADERS, data=json.dumps(body).encode())
    with urllib.request.urlopen(req, timeout=60) as r:
        ndjson = r.read().decode()
    NDJSON_OUT.write_text(ndjson)
    print(f"\n  Wrote {NDJSON_OUT} ({len(ndjson)} bytes, {ndjson.count(chr(10))} lines)")


if __name__ == "__main__":
    print("Ensuring security-ml data view exists...")
    ensure_ml_data_view()
    print("\nBuilding ML vs Deterministic dashboard...")
    build_dashboard()
    print("\nExporting NDJSON...")
    export_ndjson()
    print("\nDONE — open Kibana -> Dashboards -> 'ML vs Deterministic Detection'")
    print(f"      URL: {KIBANA_URL}/app/dashboards#/view/{DASHBOARD_ID}")
