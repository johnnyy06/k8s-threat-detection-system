#!/usr/bin/env python3
"""
Construiește Dashboard "Per-Attack-Scenario Investigation" — parametrizat cu
Options List Control pe câmpul `tags`, permite drill-down per scenariu de atac.

Idee: user pică scenario_NN din dropdown → toate panel-urile filtrează automat.
Fără selecție = vede toate scenariile cumulat (mod overview).

9 panels + 1 control:
  - Control: Options List pe `tags` (search "scenario_" pentru a filtra dropdown-ul)
  1. KPI detections in scenario
  2. KPI unique rules fired
  3. KPI Critical+High detections
  4. KPI affected pods (unique count)
  5. Detections over time (line)
  6. Top rules fired (bar) + Severity distribution (pie)
  7. Event stream (saved search) — chronological detecții
  8. Pods involved (bar)
  9. Processes involved (bar)
  10. Markdown panel — referință scenarii + cum se rulează
"""

import json
import sys
import urllib.request
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from _config import KIBANA_URL, DATA_VIEW_ECS_ID  # noqa: E402

# Pentru per-scenario dashboard folosim DOAR data view-ul security-ecs:
# - controlul Options List filtrează pe runtime field `scenario` (definit doar acolo)
# - panel-urile trebuie să folosească același data view ca să primească filtrul
# - pre-ECS data n-ar avea oricum rule.name/kubernetes.* populate
DATA_VIEW_ID = DATA_VIEW_ECS_ID  # toate panel-urile folosesc security-ecs aici
DASHBOARD_ID = "thesis-per-scenario-investigation"
NDJSON_OUT = Path(__file__).parent / "dashboard.ndjson"
SCENARIO_CONTROL_ID = "scenario-selector-001"

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


def ensure_scenario_runtime_field():
    """
    Adaugă (idempotent) un runtime field `scenario` la data view security-ecs
    care extrage doar tag-urile scenario_NN din array-ul tags[]. Necesar pentru
    ca Options List Control să arate DOAR scenariile noastre, nu toate tag-urile
    (T1552, falco, custom_rule, mitre_*, etc.).
    """
    body = {
        "name": "scenario",
        "runtimeField": {
            "type": "keyword",
            "script": {
                "source": 'for (def t : doc["tags"]) { if (t.startsWith("scenario_")) emit(t); }'
            }
        }
    }
    try:
        api("PUT", f"/api/data_views/data_view/{DATA_VIEW_ECS_ID}/runtime_field", body)
        print("  [runtime field] scenario added/updated on security-ecs")
    except urllib.error.HTTPError as e:
        sys.stderr.write(f"Warning: runtime field creation failed: {e.code}\n")


# -----------------------------------------------------------------------------
# Lens helpers
# -----------------------------------------------------------------------------

def lens_ref(layer_id):
    return {"type": "index-pattern", "id": DATA_VIEW_ID,
            "name": f"indexpattern-datasource-layer-{layer_id}"}


def count_col(label="Count of records", custom=False):
    out = {"label": label, "dataType": "number", "operationType": "count",
           "isBucketed": False, "scale": "ratio", "sourceField": "___records___"}
    if custom:
        out["customLabel"] = True
    return out


def cardinality_col(field, label="Unique count", custom=False):
    out = {"label": label, "dataType": "number", "operationType": "unique_count",
           "isBucketed": False, "scale": "ratio", "sourceField": field,
           "params": {"emptyAsNull": True}}
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

SCENARIO_FILTER = 'tags : scenario_*'  # arată doar scenarii dacă nu e selectat unul


def make_metric(panel_id, title, op="count", field=None, query=SCENARIO_FILTER):
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


def make_line(panel_id, title, query=SCENARIO_FILTER):
    body = {
        "attributes": {
            "title": title, "description": "", "visualizationType": "lnsXY",
            "state": {
                "visualization": {
                    "legend": {"isVisible": False, "position": "right"},
                    "valueLabels": "hide",
                    "fittingFunction": "None",
                    "preferredSeriesType": "line",
                    "layers": [{
                        "layerId": "lay1", "layerType": "data",
                        "accessors": ["col-count"], "position": "top",
                        "seriesType": "line", "showGridlines": False,
                        "xAccessor": "col-time",
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
                                "columnOrder": ["col-time", "col-count"],
                                "columns": {
                                    "col-time": date_hist_col(),
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


def make_terms_bar(panel_id, title, field, query=SCENARIO_FILTER, size=10, label="Top values"):
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


def make_pie_filters(panel_id, title, filters, query=SCENARIO_FILTER, shape="pie"):
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
                                    "col-slice": {
                                        "label": "Severity", "dataType": "string",
                                        "operationType": "filters",
                                        "isBucketed": True, "scale": "ordinal",
                                        "sourceField": "___records___",
                                        "params": {
                                            "filters": [
                                                {"label": f["label"],
                                                 "input": {"query": f["query"], "language": "kuery"}}
                                                for f in filters
                                            ]
                                        },
                                    },
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
# Saved search
# -----------------------------------------------------------------------------

def make_saved_search(search_id, title, columns, query="", sort_field="@timestamp",
                       sort_dir="desc"):
    search_source = {
        "query": {"query": query, "language": "kuery"},
        "filter": [],
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
    }
    body = {
        "attributes": {
            "title": title, "description": "",
            "columns": columns,
            "sort": [[sort_field, sort_dir]],
            "rowHeight": 1, "rowsPerPage": 100,
            "isTextBasedQuery": False,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(search_source),
            },
        },
        "references": [{
            "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
            "type": "index-pattern",
            "id": DATA_VIEW_ECS_ID,
        }],
    }
    return api("POST", f"/api/saved_objects/search/{search_id}?overwrite=true", body)


# -----------------------------------------------------------------------------
# Dashboard layout
# -----------------------------------------------------------------------------

PANELS = [
    # Row 0: 4 KPIs (y=0..6)
    ("kpi-detections", "metric", "lens",
        {"title": "Detections in scenario"},
        12, 6, 0, 0),
    ("kpi-rules", "metric", "lens",
        {"title": "Unique rules fired", "op": "unique_count", "field": "rule.name"},
        12, 6, 12, 0),
    ("kpi-critical", "metric", "lens",
        {"title": "Critical+High (sev≤3)",
         "query": f"{SCENARIO_FILTER} and event.severity <= 3"},
        12, 6, 24, 0),
    ("kpi-pods", "metric", "lens",
        {"title": "Affected pods", "op": "unique_count", "field": "kubernetes.pod.name"},
        12, 6, 36, 0),

    # Row 1: Timeline (full width) — y=6..18
    ("timeline", "line", "lens",
        {"title": "Detections over time"},
        48, 12, 0, 6),

    # Row 2: Top rules + Severity (y=18..32)
    ("top-rules", "terms_bar", "lens",
        {"title": "Rules fired in scenario", "field": "rule.name",
         "size": 15, "label": "Rule"},
        32, 14, 0, 18),
    ("severity", "pie_filters", "lens",
        {"title": "Severity distribution",
         "filters": [
             {"label": "Emergency/Alert/Critical", "query": f"{SCENARIO_FILTER} and event.severity <= 2"},
             {"label": "Error",                    "query": f"{SCENARIO_FILTER} and event.severity : 3"},
             {"label": "Warning",                  "query": f"{SCENARIO_FILTER} and event.severity : 4"},
             {"label": "Notice",                   "query": f"{SCENARIO_FILTER} and event.severity : 5"},
             {"label": "Informational",            "query": f"{SCENARIO_FILTER} and event.severity : 6"},
         ]},
        16, 14, 32, 18),

    # Row 3: Event stream (full width) — y=32..56
    ("event-stream", "saved_search", "search",
        {"title": "Event stream — pick a scenario from dropdown above to filter",
         "columns": [
             "@timestamp", "rule.name", "event.severity",
             "kubernetes.pod.name", "process.name", "process.command_line",
             "file.path", "destination.ip",
         ],
         "query": "tags : scenario_*"},
        48, 22, 0, 32),

    # Row 4: Pods + processes (y=54..68)
    ("pods", "terms_bar", "lens",
        {"title": "Pods involved", "field": "kubernetes.pod.name",
         "size": 8, "label": "Pod"},
        24, 12, 0, 54),
    ("procs", "terms_bar", "lens",
        {"title": "Processes involved", "field": "process.name",
         "size": 8, "label": "Process"},
        24, 12, 24, 54),
]


def build_panel(panel_kind, panel_id, args):
    builders = {
        "metric":       make_metric,
        "line":         make_line,
        "terms_bar":    make_terms_bar,
        "pie_filters":  make_pie_filters,
        "saved_search": make_saved_search,
    }
    if panel_kind not in builders:
        raise ValueError(f"unknown panel kind: {panel_kind}")
    return builders[panel_kind](panel_id, **args)


# -----------------------------------------------------------------------------
# Controls (Options List on `tags` field)
# -----------------------------------------------------------------------------

def build_control_group():
    """
    Returnează controlGroupInput JSON pentru dashboard — un Options List pe `tags`.
    User caută "scenario_" în dropdown ca să filtreze la scenariile noastre.
    """
    control = {
        SCENARIO_CONTROL_ID: {
            "order": 0,
            "width": "medium",
            "grow": True,
            "type": "optionsListControl",
            "explicitInput": {
                "id": SCENARIO_CONTROL_ID,
                "dataViewId": DATA_VIEW_ECS_ID,
                # Folosim runtime field `scenario` (vezi ensure_scenario_runtime_field).
                # Dropdown-ul afișează DOAR scenario_01..08, nu toate tag-urile.
                "fieldName": "scenario",
                "title": "Scenario",
                "selectedOptions": [],
                "singleSelect": True,
                "exclude": False,
                "existsSelected": False,
                "hideSort": False,
                "hideExclude": False,
                "hideExists": False,
                "placeholder": "Select scenario...",
                "enhancements": {},
            },
        }
    }
    return {
        "panelsJSON": json.dumps(control),
        "controlStyle": "oneLine",
        "chainingSystem": "HIERARCHICAL",
    }


# -----------------------------------------------------------------------------
# Build & export
# -----------------------------------------------------------------------------

def build_dashboard():
    panels_meta = []
    references = [
        # Referință la data view-ul folosit de control
        {"name": f"controlGroup_{SCENARIO_CONTROL_ID}:optionsListDataView",
         "type": "index-pattern", "id": DATA_VIEW_ECS_ID},
    ]
    for i, (suffix, kind, obj_type, args, w, h, x, y) in enumerate(PANELS):
        panel_id = f"thesis-per-scenario-{suffix}"
        print(f"  [{i+1:2d}/{len(PANELS)}] {kind:13s} → {panel_id} (type={obj_type})")
        build_panel(kind, panel_id, args)
        ref_name = f"panel_{i}"
        panels_meta.append({
            "version": "8.19.10",
            "type": obj_type,
            "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)},
            "panelIndex": str(i),
            "embeddableConfig": {"enhancements": {}},
            "panelRefName": ref_name,
            "title": args.get("title", "panel"),
        })
        references.append({"name": ref_name, "type": obj_type, "id": panel_id})

    dashboard_body = {
        "attributes": {
            "title": "Per-Attack-Scenario Investigation",
            "description": ("Dashboard parametrizat cu Options List Control pe câmpul `tags`. "
                            "Tag-urile `scenario_NN` sunt populate de regulile Falco custom — "
                            "fiecare scenariu (01-08) lasă o amprentă unică. "
                            "Folosire: în dropdown-ul de sus, caută 'scenario_' și pică scenariul. "
                            "Toate panel-urile vor filtra automat."),
            "panelsJSON": json.dumps(panels_meta),
            "optionsJSON": json.dumps({
                "useMargins": True, "syncColors": False, "syncCursor": True,
                "syncTooltips": False, "hidePanelTitles": False,
            }),
            "version": 1,
            "timeRestore": True,
            "timeTo": "now",
            "timeFrom": "now-7d",
            "refreshInterval": {"pause": True, "value": 30000},
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
            },
            "controlGroupInput": build_control_group(),
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
    print("Ensuring scenario runtime field on security-ecs data view...")
    ensure_scenario_runtime_field()
    print("\nBuilding Per-Attack-Scenario Investigation dashboard...")
    build_dashboard()
    print("\nExporting NDJSON...")
    export_ndjson()
    print("\nDONE — open Kibana → Dashboards → 'Per-Attack-Scenario Investigation'")
    print(f"      URL: {KIBANA_URL}/app/dashboards#/view/{DASHBOARD_ID}")
    print("      Folosire: caută 'scenario_' în dropdown-ul Scenario, pică unul.")
