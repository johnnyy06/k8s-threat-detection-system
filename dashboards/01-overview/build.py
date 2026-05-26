#!/usr/bin/env python3
"""
Construiește Dashboard-ul "Overview — Security Posture" în Kibana via Saved Objects API.

Pași:
  1. POST 11 Lens visualizations
  2. POST 1 dashboard care le referă cu grid positions
  3. EXPORT NDJSON in dashboards/01-overview.ndjson

Idempotent (foloseste overwrite=true).
"""

import json
import sys
import uuid
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from _config import KIBANA_URL, DATA_VIEW_ID  # noqa: E402

DASHBOARD_ID = "thesis-overview-security-posture"
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
# Lens panel builders
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


def make_metric(panel_id, title, query="", color=None, subtitle=""):
    """Lens metric (single KPI tile). customLabel=True ascunde sub-titlul 'Count of records'."""
    body = {
        "attributes": {
            "title": title, "description": "", "visualizationType": "lnsMetric",
            "state": {
                "visualization": {
                    "layerId": "lay1", "layerType": "data", "metricAccessor": "col-count",
                    "subtitle": subtitle,
                    **({"color": color} if color else {}),
                },
                "query": {"query": query, "language": "kuery"},
                "filters": [],
                "datasourceStates": {
                    "formBased": {
                        "layers": {
                            "lay1": {
                                "columnOrder": ["col-count"],
                                # Label gol = ascunde sub-titlul redundant; titlul panel-ului
                                # rămâne în header. customLabel=True spune lui Lens să nu
                                # populeze default "Count of records".
                                "columns": {"col-count": count_col(" ", custom=True)},
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


def make_terms_bar(panel_id, title, field, query="", size=10, label="Top values"):
    """Lens horizontal bar chart — top values of a field."""
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
                    "axisTitlesVisibilitySettings": {
                        "x": False, "yLeft": False, "yRight": False,
                    },
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


def make_timeline_area(panel_id, title, split_by="observer.product"):
    """Lens stacked area chart — events over time, broken down by a field."""
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
                    "axisTitlesVisibilitySettings": {
                        "x": False, "yLeft": False, "yRight": False,
                    },
                    "tickLabelsVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
                    "labelsOrientation": {"x": 0, "yLeft": 0, "yRight": 0},
                    "gridlinesVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
                },
                "query": {"query": "", "language": "kuery"},
                "filters": [],
                "datasourceStates": {
                    "formBased": {
                        "layers": {
                            "lay1": {
                                "columnOrder": ["col-time", "col-split", "col-count"],
                                "columns": {
                                    "col-time": date_hist_col(),
                                    "col-split": terms_col(split_by, "Top tool", size=5),
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


def filters_col(filters, label="Severity"):
    """
    Bucketing pe filtre KQL custom — fiecare bucket are un label propriu.
    Folosit pentru a transforma valori numerice (event.severity 0..7) în etichete text.
    """
    return {
        "label": label, "dataType": "string", "operationType": "filters",
        "isBucketed": True, "scale": "ordinal", "sourceField": "___records___",
        "params": {
            "filters": [
                {"label": f["label"],
                 "input": {"query": f["query"], "language": "kuery"}}
                for f in filters
            ]
        },
    }


def make_pie_filters(panel_id, title, filters, query="", shape="pie", label="Severity"):
    """Pie / donut chart cu bucket-uri custom (KQL filter → label)."""
    body = {
        "attributes": {
            "title": title, "description": "", "visualizationType": "lnsPie",
            "state": {
                "visualization": {
                    "shape": shape,
                    "layers": [{
                        "layerId": "lay1", "layerType": "data",
                        "primaryGroups": ["col-slice"],
                        "metrics": ["col-count"],
                        "numberDisplay": "percent",
                        "categoryDisplay": "default",
                        "legendDisplay": "default",
                        "nestedLegend": False,
                        "legendPosition": "right",
                        "percentDecimals": 1,
                    }],
                },
                "query": {"query": query, "language": "kuery"},
                "filters": [],
                "datasourceStates": {
                    "formBased": {
                        "layers": {
                            "lay1": {
                                "columnOrder": ["col-slice", "col-count"],
                                "columns": {
                                    "col-slice": filters_col(filters, label),
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


def make_pie(panel_id, title, field, query="", shape="pie", size=8, label=""):
    """Lens pie / donut chart."""
    body = {
        "attributes": {
            "title": title, "description": "", "visualizationType": "lnsPie",
            "state": {
                "visualization": {
                    "shape": shape,
                    "layers": [{
                        "layerId": "lay1", "layerType": "data",
                        "primaryGroups": ["col-slice"],
                        "metrics": ["col-count"],
                        "numberDisplay": "percent",
                        "categoryDisplay": "default",
                        "legendDisplay": "default",
                        "nestedLegend": False,
                        "legendPosition": "right",
                        "percentDecimals": 1,
                    }],
                },
                "query": {"query": query, "language": "kuery"},
                "filters": [],
                "datasourceStates": {
                    "formBased": {
                        "layers": {
                            "lay1": {
                                "columnOrder": ["col-slice", "col-count"],
                                "columns": {
                                    "col-slice": terms_col(field, label or field, size=size),
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


def make_treemap(panel_id, title, outer_field, inner_field, query=""):
    """Lens treemap — two levels of grouping."""
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
                                    "col-inner": terms_col(inner_field, inner_field, size=20),
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


# -----------------------------------------------------------------------------
# Dashboard assembly
# -----------------------------------------------------------------------------

PANELS = [
    # (panel_id_suffix, builder, args, grid_w, grid_h, grid_x, grid_y, title_override)
    ("kpi-total",       "metric",   {"title": "Total events", "query": ""},
        12, 6, 0, 0),
    ("kpi-falco",       "metric",   {"title": "Falco alerts", "query": "tags : \"falco\""},
        12, 6, 12, 0),
    ("kpi-suricata",    "metric",   {"title": "Suricata events", "query": "tags : \"suricata\""},
        12, 6, 24, 0),
    ("kpi-critical",    "metric",   {"title": "Critical+High (sev≤3)", "query": "event.severity <= 3"},
        12, 6, 36, 0),
    ("timeline",        "timeline", {"title": "Event timeline — by tool"},
        48, 12, 0, 6),
    ("top-falco",       "terms_bar",{"title": "Top Falco rules", "field": "rule.name",
                                     "query": "tags : \"falco\"", "size": 10, "label": "Falco rule"},
        24, 14, 0, 18),
    ("top-suricata",    "terms_bar",{"title": "Top Suricata signatures",
                                     "field": "rule.name",
                                     # Exclude regulile SURICATA* (baseline protocol anomalies — TCP/HTTP
                                     # parse errors, NU detecții de amenințare). Real detections încep
                                     # cu "ET " (Emerging Threats) sau alți vendor prefixes.
                                     "query": "tags : \"suricata\" and event_type : \"alert\" "
                                              "and not rule.name : SURICATA*",
                                     "size": 10,
                                     "label": "Suricata signature"},
        24, 14, 24, 18),
    # === Rând nou: Suricata observability complementară ===
    # Suricata e mai puternic ca telemetrie network (flow/dns/http/tls) decât ca
    # signature engine în setup-ul nostru. Aceste 2 panel-uri arată asta direct.
    ("suricata-types",  "pie",      {"title": "Suricata events by type",
                                     "field": "event_type.keyword",
                                     "query": "tags : \"suricata\"",
                                     "shape": "donut", "size": 10, "label": "event_type"},
        24, 14, 0, 32),
    ("suricata-dests",  "terms_bar",{"title": "Top Suricata destinations (network telemetry)",
                                     "field": "destination.ip",
                                     "query": "tags : \"suricata\"",
                                     "size": 10, "label": "destination.ip"},
        24, 14, 24, 32),
    # === Rând: severity / by-node / MITRE ===
    ("severity",        "pie_filters", {
        "title": "Severity distribution",
        "shape": "pie",
        "label": "Severity",
        # Bucket-uri etichetate text — mai user-friendly decât numere event.severity 0..7
        "filters": [
            {"label": "Emergency / Alert / Critical", "query": "event.severity <= 2"},
            {"label": "Error",                        "query": "event.severity : 3"},
            {"label": "Warning",                      "query": "event.severity : 4"},
            {"label": "Notice",                       "query": "event.severity : 5"},
            {"label": "Informational",                "query": "event.severity : 6"},
            {"label": "Debug",                        "query": "event.severity : 7"},
        ],
    },
        16, 14, 0, 46),
    ("by-node",         "pie",      {"title": "Events by node", "field": "observer.hostname",
                                     "shape": "donut", "label": "Node"},
        16, 14, 16, 46),
    ("mitre",           "treemap",  {"title": "MITRE ATT&CK coverage",
                                     "outer_field": "threat.tactic.name",
                                     "inner_field": "threat.technique.name",
                                     "query": "threat.framework : \"MITRE ATT&CK\""},
        16, 14, 32, 46),
    ("top-namespaces",  "terms_bar",{"title": "Top Kubernetes namespaces", "field": "kubernetes.namespace",
                                     "query": "tags : \"falco\"", "size": 10, "label": "Namespace"},
        48, 12, 0, 60),
]


def build_panel(panel_kind, panel_id, args):
    if panel_kind == "metric":
        return make_metric(panel_id, **args)
    if panel_kind == "timeline":
        return make_timeline_area(panel_id, **args)
    if panel_kind == "terms_bar":
        return make_terms_bar(panel_id, **args)
    if panel_kind == "pie":
        return make_pie(panel_id, **args)
    if panel_kind == "pie_filters":
        return make_pie_filters(panel_id, **args)
    if panel_kind == "treemap":
        return make_treemap(panel_id, **args)
    raise ValueError(f"Unknown panel kind: {panel_kind}")


def build_dashboard():
    panels_meta = []
    references = []
    for i, (suffix, kind, args, w, h, x, y) in enumerate(PANELS):
        panel_id = f"thesis-overview-{suffix}"
        print(f"  [{i+1:2d}/{len(PANELS)}] {kind:9s} → {panel_id}")
        build_panel(kind, panel_id, args)
        panel_ref_name = f"panel_{i}"
        panels_meta.append({
            "version": "8.19.10",
            "type": "lens",
            "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)},
            "panelIndex": str(i),
            "embeddableConfig": {"enhancements": {}},
            "panelRefName": panel_ref_name,
            "title": args.get("title", "panel"),
        })
        references.append({"name": panel_ref_name, "type": "lens", "id": panel_id})

    dashboard_body = {
        "attributes": {
            "title": "Overview — Security Posture",
            "description": "Top-level security posture: alerts, severity, MITRE, K8s context. "
                           "Sursă date: index unificat security-* (Falco + Suricata via ECS).",
            "panelsJSON": json.dumps(panels_meta),
            "optionsJSON": json.dumps({
                "useMargins": True, "syncColors": False, "syncCursor": True,
                "syncTooltips": False, "hidePanelTitles": False,
            }),
            "version": 1,
            "timeRestore": True,
            "timeTo": "now",
            "timeFrom": "now-24h",
            "refreshInterval": {"pause": True, "value": 30000},
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
            },
        },
        "references": references,
    }
    print(f"  [dashboard] thesis-overview-security-posture")
    api("POST", f"/api/saved_objects/dashboard/{DASHBOARD_ID}?overwrite=true", dashboard_body)


def export_ndjson():
    """Exportă dashboard-ul + toate Lens panels ca NDJSON pentru versionare."""
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
    print("Building Overview dashboard...")
    build_dashboard()
    print("\nExporting NDJSON...")
    export_ndjson()
    print("\nDONE — open Kibana → Dashboards → 'Overview — Security Posture'")
    print(f"      URL: {KIBANA_URL}/app/dashboards#/view/{DASHBOARD_ID}")
