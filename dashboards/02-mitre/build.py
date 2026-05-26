#!/usr/bin/env python3
"""
Construiește Dashboard "MITRE ATT&CK Coverage" — focus pe tehnici/tactici detectate.

10 panels:
  1. KPI total MITRE-tagged events
  2. KPI unique techniques
  3. KPI unique tactics
  4. KPI Critical MITRE events
  5. Tactic timeline (stacked area)
  6. Top tactics (bar)
  7. Top techniques (bar)
  8. MITRE coverage treemap (full width)
  9. Technique → Falco rule mapping (data table)
 10. Top pods + top processes affected
"""

import json
import sys
import urllib.request
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from _config import KIBANA_URL, DATA_VIEW_ID  # noqa: E402

DASHBOARD_ID = "thesis-mitre-attck-coverage"
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


# -----------------------------------------------------------------------------
# Lens column builders (reusable)
# -----------------------------------------------------------------------------

def lens_ref(layer_id):
    return {"type": "index-pattern", "id": DATA_VIEW_ID,
            "name": f"indexpattern-datasource-layer-{layer_id}"}


def count_col(label="Count of records", custom=False):
    out = {
        "label": label, "dataType": "number", "operationType": "count",
        "isBucketed": False, "scale": "ratio", "sourceField": "___records___",
    }
    if custom:
        out["customLabel"] = True
    return out


def cardinality_col(field, label="Unique count", custom=False):
    """Cardinality / unique_count aggregation — folosit pentru KPI-uri 'unique X'."""
    out = {
        "label": label, "dataType": "number", "operationType": "unique_count",
        "isBucketed": False, "scale": "ratio", "sourceField": field,
        "params": {"emptyAsNull": True},
    }
    if custom:
        out["customLabel"] = True
    return out


def terms_col(field, label, size=10, order_by="col-count", order_dir="desc"):
    return {
        "label": label, "dataType": "string", "operationType": "terms",
        "isBucketed": True, "scale": "ordinal", "sourceField": field,
        "params": {
            "size": size, "orderBy": {"type": "column", "columnId": order_by},
            "orderDirection": order_dir, "otherBucket": False, "missingBucket": False,
            "parentFormat": {"id": "terms"},
        },
    }


def date_hist_col(interval="auto"):
    return {
        "label": "@timestamp", "dataType": "date", "operationType": "date_histogram",
        "isBucketed": True, "scale": "interval", "sourceField": "@timestamp",
        "params": {"interval": interval, "includeEmptyRows": True, "dropPartials": False},
    }


# -----------------------------------------------------------------------------
# Panel builders
# -----------------------------------------------------------------------------

# Filtru global aplicat tuturor panel-urilor: doar evenimente MITRE-tagged
MITRE_FILTER = 'threat.framework : "MITRE ATT&CK"'


def make_metric(panel_id, title, op="count", field=None, query=MITRE_FILTER, subtitle=""):
    """KPI panel: count sau unique_count. Label gol pe coloană = sub-titlul ascuns;
    titlul panel-ului rămâne în header (nu duplicat)."""
    if op == "count":
        col = count_col(" ", custom=True)
    elif op == "unique_count":
        col = cardinality_col(field, " ", custom=True)
    else:
        raise ValueError(f"unknown op: {op}")

    body = {
        "attributes": {
            "title": title, "description": "", "visualizationType": "lnsMetric",
            "state": {
                "visualization": {
                    "layerId": "lay1", "layerType": "data", "metricAccessor": "col-m",
                    "subtitle": subtitle,
                },
                "query": {"query": query, "language": "kuery"},
                "filters": [],
                "datasourceStates": {
                    "formBased": {
                        "layers": {
                            "lay1": {
                                "columnOrder": ["col-m"],
                                "columns": {"col-m": col},
                                "indexPatternId": DATA_VIEW_ID,
                            }
                        }
                    },
                    "textBased": {"layers": {}},
                },
            },
        },
        "references": [lens_ref("lay1")],
    }
    return api("POST", f"/api/saved_objects/lens/{panel_id}?overwrite=true", body)


def make_terms_bar(panel_id, title, field, query=MITRE_FILTER, size=10, label="Top values"):
    body = {
        "attributes": {
            "title": title, "description": "", "visualizationType": "lnsXY",
            "state": {
                "visualization": {
                    "legend": {"isVisible": False, "position": "right"},
                    "valueLabels": "show",
                    "preferredSeriesType": "bar_horizontal",
                    "layers": [{
                        "layerId": "lay1", "layerType": "data",
                        "accessors": ["col-count"], "position": "top",
                        "seriesType": "bar_horizontal", "showGridlines": False,
                        "xAccessor": "col-terms",
                    }],
                    "axisTitlesVisibilitySettings": {"x": False, "yLeft": False, "yRight": False},
                    "tickLabelsVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
                    "labelsOrientation": {"x": 0, "yLeft": 0, "yRight": 0},
                    "gridlinesVisibilitySettings": {"x": True, "yLeft": False, "yRight": False},
                },
                "query": {"query": query, "language": "kuery"},
                "filters": [],
                "datasourceStates": {
                    "formBased": {
                        "layers": {
                            "lay1": {
                                "columnOrder": ["col-terms", "col-count"],
                                "columns": {
                                    "col-terms": terms_col(field, label, size=size),
                                    "col-count": count_col(),
                                },
                                "indexPatternId": DATA_VIEW_ID,
                            }
                        }
                    },
                    "textBased": {"layers": {}},
                },
            },
        },
        "references": [lens_ref("lay1")],
    }
    return api("POST", f"/api/saved_objects/lens/{panel_id}?overwrite=true", body)


def make_stacked_area(panel_id, title, split_by, query=MITRE_FILTER, split_size=12):
    """Stacked area chart — events over time, broken down by a field."""
    body = {
        "attributes": {
            "title": title, "description": "", "visualizationType": "lnsXY",
            "state": {
                "visualization": {
                    "legend": {"isVisible": True, "position": "right"},
                    "valueLabels": "hide",
                    "fittingFunction": "None",
                    "preferredSeriesType": "area_stacked",
                    "layers": [{
                        "layerId": "lay1", "layerType": "data",
                        "accessors": ["col-count"], "position": "top",
                        "seriesType": "area_stacked", "showGridlines": False,
                        "xAccessor": "col-time",
                        "splitAccessor": "col-split",
                    }],
                    "axisTitlesVisibilitySettings": {"x": False, "yLeft": False, "yRight": False},
                    "tickLabelsVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
                    "labelsOrientation": {"x": 0, "yLeft": 0, "yRight": 0},
                    "gridlinesVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
                },
                "query": {"query": query, "language": "kuery"},
                "filters": [],
                "datasourceStates": {
                    "formBased": {
                        "layers": {
                            "lay1": {
                                "columnOrder": ["col-time", "col-split", "col-count"],
                                "columns": {
                                    "col-time": date_hist_col(),
                                    "col-split": terms_col(split_by, split_by, size=split_size),
                                    "col-count": count_col(),
                                },
                                "indexPatternId": DATA_VIEW_ID,
                            }
                        }
                    },
                    "textBased": {"layers": {}},
                },
            },
        },
        "references": [lens_ref("lay1")],
    }
    return api("POST", f"/api/saved_objects/lens/{panel_id}?overwrite=true", body)


def make_treemap(panel_id, title, outer_field, inner_field, query=MITRE_FILTER):
    body = {
        "attributes": {
            "title": title, "description": "", "visualizationType": "lnsPie",
            "state": {
                "visualization": {
                    "shape": "treemap",
                    "layers": [{
                        "layerId": "lay1", "layerType": "data",
                        "primaryGroups": ["col-outer", "col-inner"],
                        "metrics": ["col-count"],
                        "numberDisplay": "percent",
                        "categoryDisplay": "default",
                        "legendDisplay": "show",
                        "legendPosition": "right",
                        "nestedLegend": True,
                    }],
                },
                "query": {"query": query, "language": "kuery"},
                "filters": [],
                "datasourceStates": {
                    "formBased": {
                        "layers": {
                            "lay1": {
                                "columnOrder": ["col-outer", "col-inner", "col-count"],
                                "columns": {
                                    "col-outer": terms_col(outer_field, outer_field, size=15),
                                    "col-inner": terms_col(inner_field, inner_field, size=25),
                                    "col-count": count_col(),
                                },
                                "indexPatternId": DATA_VIEW_ID,
                            }
                        }
                    },
                    "textBased": {"layers": {}},
                },
            },
        },
        "references": [lens_ref("lay1")],
    }
    return api("POST", f"/api/saved_objects/lens/{panel_id}?overwrite=true", body)


def make_datatable(panel_id, title, group_fields, query=MITRE_FILTER, page_size=20):
    """
    Lens data table cu N coloane de grupare + 1 coloană de numărare.
    group_fields = [(field, label, size), ...]
    """
    col_ids = [f"col-g{i}" for i in range(len(group_fields))] + ["col-count"]
    columns_meta = []
    cols = {}
    for i, (field, label, size) in enumerate(group_fields):
        cid = f"col-g{i}"
        cols[cid] = terms_col(field, label, size=size)
        columns_meta.append({"columnId": cid, "isTransposed": False})
    cols["col-count"] = count_col()
    columns_meta.append({"columnId": "col-count", "isTransposed": False, "alignment": "right"})

    body = {
        "attributes": {
            "title": title, "description": "", "visualizationType": "lnsDatatable",
            "state": {
                "visualization": {
                    "layerId": "lay1", "layerType": "data",
                    "columns": columns_meta,
                    "paging": {"enabled": True, "size": page_size},
                },
                "query": {"query": query, "language": "kuery"},
                "filters": [],
                "datasourceStates": {
                    "formBased": {
                        "layers": {
                            "lay1": {
                                "columnOrder": col_ids,
                                "columns": cols,
                                "indexPatternId": DATA_VIEW_ID,
                            }
                        }
                    },
                    "textBased": {"layers": {}},
                },
            },
        },
        "references": [lens_ref("lay1")],
    }
    return api("POST", f"/api/saved_objects/lens/{panel_id}?overwrite=true", body)


# -----------------------------------------------------------------------------
# Dashboard layout
# -----------------------------------------------------------------------------

PANELS = [
    # KPIs (row 0, y=0..6)
    ("kpi-total",      "metric",
        {"title": "MITRE-tagged events", "op": "count"},
        12, 6, 0, 0),
    ("kpi-techniques", "metric",
        {"title": "Unique techniques", "op": "unique_count", "field": "threat.technique.id"},
        12, 6, 12, 0),
    ("kpi-tactics",    "metric",
        {"title": "Unique tactics", "op": "unique_count", "field": "threat.tactic.id"},
        12, 6, 24, 0),
    ("kpi-critical",   "metric",
        {"title": "Critical+High MITRE (sev≤3)",
         "op": "count",
         "query": f'{MITRE_FILTER} and event.severity <= 3'},
        12, 6, 36, 0),

    # Tactic timeline (row 1, y=6..20)
    ("tactic-timeline", "stacked_area",
        {"title": "Tactic timeline — events over time by tactic",
         "split_by": "threat.tactic.name"},
        48, 14, 0, 6),

    # Top tactics + top techniques (row 2, y=20..34)
    ("top-tactics", "terms_bar",
        {"title": "Top tactics", "field": "threat.tactic.name", "size": 12, "label": "Tactic"},
        24, 14, 0, 20),
    ("top-techniques", "terms_bar",
        {"title": "Top techniques", "field": "threat.technique.name", "size": 15,
         "label": "Technique"},
        24, 14, 24, 20),

    # MITRE coverage matrix (row 3, y=34..52) — full width, larger
    ("coverage-matrix", "treemap",
        {"title": "MITRE coverage matrix (tactic → technique)",
         "outer_field": "threat.tactic.name",
         "inner_field": "threat.technique.name"},
        48, 18, 0, 34),

    # Technique → Rule mapping (row 4, y=52..70)
    ("technique-rule-table", "datatable",
        {"title": "Technique → Falco rule mapping (which rules contribute to each technique)",
         "group_fields": [
             ("threat.technique.name", "Technique", 15),
             ("threat.technique.id",   "Technique ID", 15),
             ("rule.name",             "Falco rule", 50),
         ],
         "page_size": 25},
        48, 18, 0, 52),

    # Pods + processes affected (row 5, y=70..84) — size 5 ca să eliminăm bar-uri goale
    ("affected-pods", "terms_bar",
        {"title": "Top pods with MITRE detections", "field": "kubernetes.pod.name",
         "size": 5, "label": "Pod"},
        24, 14, 0, 70),
    ("affected-procs", "terms_bar",
        {"title": "Top processes triggering MITRE rules", "field": "process.name",
         "size": 5, "label": "Process"},
        24, 14, 24, 70),
]


def build_panel(panel_kind, panel_id, args):
    builders = {
        "metric":        make_metric,
        "terms_bar":     make_terms_bar,
        "stacked_area":  make_stacked_area,
        "treemap":       make_treemap,
        "datatable":     make_datatable,
    }
    if panel_kind not in builders:
        raise ValueError(f"unknown panel kind: {panel_kind}")
    return builders[panel_kind](panel_id, **args)


def build_dashboard():
    panels_meta = []
    references = []
    for i, (suffix, kind, args, w, h, x, y) in enumerate(PANELS):
        panel_id = f"thesis-mitre-{suffix}"
        print(f"  [{i+1:2d}/{len(PANELS)}] {kind:13s} → {panel_id}")
        build_panel(kind, panel_id, args)
        ref_name = f"panel_{i}"
        panels_meta.append({
            "version": "8.19.10",
            "type": "lens",
            "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)},
            "panelIndex": str(i),
            "embeddableConfig": {"enhancements": {}},
            "panelRefName": ref_name,
            "title": args.get("title", "panel"),
        })
        references.append({"name": ref_name, "type": "lens", "id": panel_id})

    dashboard_body = {
        "attributes": {
            "title": "MITRE ATT&CK Coverage",
            "description": ("Vizualizare cap-coadă a evenimentelor mappate la framework-ul "
                            "MITRE ATT&CK. Diferențiator vs SIEM-uri vanilla — folosim direct "
                            "threat.tactic.* / threat.technique.* (ECS canonical, populate "
                            "din tagurile Falco T1xxx / mitre_xxx via Logstash ruby filter)."),
            "panelsJSON": json.dumps(panels_meta),
            "optionsJSON": json.dumps({
                "useMargins": True, "syncColors": False, "syncCursor": True,
                "syncTooltips": False, "hidePanelTitles": False,
            }),
            "version": 1,
            "timeRestore": True,
            "timeTo": "now",
            "timeFrom": "now-7d",  # default 7 days — MITRE distribution e mai informativ peste săptămână
            "refreshInterval": {"pause": True, "value": 30000},
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
            },
        },
        "references": references,
    }
    print(f"  [dashboard] {DASHBOARD_ID}")
    api("POST", f"/api/saved_objects/dashboard/{DASHBOARD_ID}?overwrite=true", dashboard_body)


def export_ndjson():
    body = {
        "objects": [{"type": "dashboard", "id": DASHBOARD_ID}],
        "includeReferencesDeep": True,
    }
    req = urllib.request.Request(
        KIBANA_URL + "/api/saved_objects/_export",
        method="POST", headers=HEADERS,
        data=json.dumps(body).encode(),
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        ndjson = r.read().decode()
    NDJSON_OUT.write_text(ndjson)
    print(f"\n  Wrote {NDJSON_OUT} ({len(ndjson)} bytes, {ndjson.count(chr(10))} lines)")


if __name__ == "__main__":
    print("Building MITRE ATT&CK Coverage dashboard...")
    build_dashboard()
    print("\nExporting NDJSON...")
    export_ndjson()
    print("\nDONE — open Kibana → Dashboards → 'MITRE ATT&CK Coverage'")
    print(f"      URL: {KIBANA_URL}/app/dashboards#/view/{DASHBOARD_ID}")
