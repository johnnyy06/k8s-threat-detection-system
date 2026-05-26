#!/usr/bin/env python3
"""
Construiește Dashboard "Cross-Tool Correlation" — demonstrează valoarea
arhitecturii cu 2 tool-uri complementare (Falco runtime + Suricata network)
asupra aceluiași index unificat security-* prin câmpuri ECS canonice.

Narativ central (vezi datele preview):
  - Falco rulează ca DaemonSet pe TOATE nodurile (node-1..node-4)
  - Suricata rulează ca systemd DOAR pe node-2
  - => node-2 e SINGURUL nod cu vizibilitate cross-tool real
  - => panelul "Events per host × tool" arată asta vizual stark

10 panels:
  1. KPI Total events
  2. KPI Falco events
  3. KPI Suricata events
  4. KPI Critical+High (sev≤3) cross-tool
  5. Cross-tool timeline overlay (stacked area by observer.product)
  6. Events per host × tool (stacked bar horizontal — KEY panel)
  7. Top Suricata destinations (network telemetry)
  8. Combined event stream (saved search, chronological mixed)
  9. Events per K8s namespace (Falco context only)
 10. Top Falco-affected pods
"""

import json
import sys
import urllib.request
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from _config import KIBANA_URL, DATA_VIEW_ID, DATA_VIEW_ECS_ID  # noqa: E402

# Pattern data view security-ecs: ES NU suportă char classes ([3-9]) în index
# patterns, deci folosim exclusion list explicit pentru cei 22 indecși pre-ECS
# (2026-05-01..22, ingestate înainte de migrația ECS din 2026-05-23).
# Pattern: "security-*,-security-2026.05.01,-security-2026.05.02,...,-security-2026.05.22"
# Motivul: saved searches sortează la nivel de shard ÎNAINTE să aplice filtre.
# Dacă vreun shard nu are field-ul (rule.name, source.ip, etc.) → eroare
# "No mapping found in order to sort on". Lens visualizations nu suferă (agregări).
DASHBOARD_ID = "thesis-cross-tool-correlation"
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


def ensure_ecs_data_view():
    """
    Asigură că data view `security-ecs` (id DATA_VIEW_ECS_ID) există cu pattern-ul
    corect. Idempotent — actualizează pattern-ul dacă e diferit.
    """
    excl = ",".join(f"-security-2026.05.{d:02d}" for d in range(1, 23))
    pattern = f"security-*,{excl}"

    body = {
        "data_view": {
            "id": DATA_VIEW_ECS_ID,
            "title": pattern,
            "name": "security-ecs",
            "timeFieldName": "@timestamp",
        },
        "override": True,
    }
    try:
        r = api("POST", "/api/data_views/data_view", body)
        print(f"  [data view] security-ecs created/updated (id={r['data_view']['id']})")
    except urllib.error.HTTPError as e:
        if e.code == 409:
            # already exists with same id — just update pattern
            api("POST", f"/api/data_views/data_view/{DATA_VIEW_ECS_ID}",
                {"data_view": {"title": pattern, "timeFieldName": "@timestamp"},
                 "refresh_fields": True})
            print(f"  [data view] security-ecs pattern refreshed")
        else:
            raise


# -----------------------------------------------------------------------------
# Lens column builders (refold din celelalte build scripts)
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


# -----------------------------------------------------------------------------
# Lens panel builders
# -----------------------------------------------------------------------------

def make_metric(panel_id, title, query="", color=None):
    body = {
        "attributes": {
            "title": title, "description": "", "visualizationType": "lnsMetric",
            "state": {
                "visualization": {
                    "layerId": "lay1", "layerType": "data", "metricAccessor": "col-count",
                    **({"color": color} if color else {}),
                },
                "query": {"query": query, "language": "kuery"},
                "filters": [],
                "datasourceStates": {
                    "formBased": {
                        "layers": {
                            "lay1": {
                                "columnOrder": ["col-count"],
                                "columns": {"col-count": count_col(" ", custom=True)},
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


def make_stacked_bar(panel_id, title, group_field, split_field, query="",
                     group_size=10, split_size=5, orientation="horizontal"):
    """
    Stacked bar chart cu sub-grupare. Idiomul "Events per X × tool":
    - group_field = câmpul de pe axa Y (ex: observer.hostname)
    - split_field = câmpul care colorează bar-urile (ex: observer.product)
    """
    series_type = "bar_horizontal_stacked" if orientation == "horizontal" else "bar_stacked"
    body = {
        "attributes": {
            "title": title, "description": "", "visualizationType": "lnsXY",
            "state": {
                "visualization": {
                    "legend": {"isVisible": True, "position": "right"},
                    "valueLabels": "show",
                    "preferredSeriesType": series_type,
                    "layers": [{
                        "layerId": "lay1", "layerType": "data",
                        "accessors": ["col-count"], "position": "top",
                        "seriesType": series_type, "showGridlines": False,
                        "xAccessor": "col-group",
                        "splitAccessor": "col-split",
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
                                "columnOrder": ["col-group", "col-split", "col-count"],
                                "columns": {
                                    "col-group": terms_col(group_field, group_field, size=group_size),
                                    "col-split": terms_col(split_field, split_field, size=split_size),
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


def make_stacked_area(panel_id, title, split_by, query="", split_size=5):
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


# -----------------------------------------------------------------------------
# Saved search builder (pentru combined event stream)
# -----------------------------------------------------------------------------

def make_saved_search(search_id, title, columns, query="", sort_field="@timestamp",
                       sort_dir="desc", row_height=1, data_view_id=None):
    """
    Saved search (Discover view) embeddable ca panel în dashboard.
    Mai potrivit decât un Lens datatable pentru event streams chronological.
    data_view_id: dacă None, folosește DATA_VIEW_ECS_ID (evită shard sort errors).
    """
    if data_view_id is None:
        data_view_id = DATA_VIEW_ECS_ID
    search_source = {
        "query": {"query": query, "language": "kuery"},
        "filter": [],
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
    }
    body = {
        "attributes": {
            "title": title,
            "description": "",
            "columns": columns,
            "sort": [[sort_field, sort_dir]],
            "rowHeight": row_height,
            "rowsPerPage": 100,
            "isTextBasedQuery": False,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(search_source),
            },
        },
        "references": [{
            "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
            "type": "index-pattern",
            "id": data_view_id,
        }],
    }
    return api("POST", f"/api/saved_objects/search/{search_id}?overwrite=true", body)


# -----------------------------------------------------------------------------
# Dashboard layout (12-col grid)
# -----------------------------------------------------------------------------

PANELS = [
    # Row 0: 4 KPIs (y=0..6)
    ("kpi-total",    "metric", "lens",
        {"title": "Total events (both tools)", "query": ""},
        12, 6, 0, 0),
    ("kpi-falco",    "metric", "lens",
        {"title": "Falco events", "query": "tags : \"falco\""},
        12, 6, 12, 0),
    ("kpi-suricata", "metric", "lens",
        {"title": "Suricata events", "query": "tags : \"suricata\""},
        12, 6, 24, 0),
    ("kpi-critical", "metric", "lens",
        {"title": "Critical+High (sev≤3)", "query": "event.severity <= 3"},
        12, 6, 36, 0),

    # Row 1: Cross-tool timeline overlay (y=6..20)
    ("timeline-overlay", "stacked_area", "lens",
        {"title": "Cross-tool timeline — Falco vs Suricata over time",
         "split_by": "observer.product"},
        48, 14, 0, 6),

    # Row 2: KEY panel — events per host × tool (y=20..34) + top destinations side
    ("per-host-tool", "stacked_bar", "lens",
        {"title": "Events per host × tool (node-2 = singurul nod cross-tool)",
         "group_field": "observer.hostname",
         "split_field": "observer.product",
         "group_size": 10, "split_size": 2,
         "orientation": "horizontal"},
        28, 14, 0, 20),
    ("top-dests", "terms_bar", "lens",
        {"title": "Top Suricata destinations (network telemetry)",
         "field": "destination.ip",
         "query": "tags : \"suricata\"",
         "size": 10, "label": "destination.ip"},
        20, 14, 28, 20),

    # Row 3: Combined event stream — saved search (y=34..58)
    # Folosește DATA_VIEW_ECS_ID (security-ecs) — limitat la indecșii cu schema ECS.
    # Necesar pentru sort: ES sortează la nivel de shard ÎNAINTE să filtreze docs.
    ("event-stream", "saved_search", "search",
        {"title": "Combined event stream (chronological, mixed Falco + Suricata)",
         "columns": [
             "@timestamp",
             "observer.product",
             "event.severity",
             "rule.name",
             "kubernetes.namespace",
             "kubernetes.pod.name",
             "process.name",
             "source.ip",
             "destination.ip",
         ],
         "query": "",
         "row_height": 1},
        48, 24, 0, 34),

    # Row 4: K8s context (y=58..72)
    ("per-namespace", "terms_bar", "lens",
        {"title": "Events per K8s namespace (Falco only — Suricata lacks K8s context)",
         "field": "kubernetes.namespace",
         "query": "tags : \"falco\" and kubernetes.namespace : *",
         "size": 10, "label": "namespace"},
        24, 14, 0, 58),
    ("top-pods", "terms_bar", "lens",
        {"title": "Top Falco-affected pods",
         "field": "kubernetes.pod.name",
         "query": "tags : \"falco\"",
         "size": 10, "label": "pod"},
        24, 14, 24, 58),
]


# -----------------------------------------------------------------------------
# Dispatch
# -----------------------------------------------------------------------------

def build_panel(panel_kind, panel_id, args):
    if panel_kind == "metric":
        return make_metric(panel_id, **args)
    if panel_kind == "terms_bar":
        return make_terms_bar(panel_id, **args)
    if panel_kind == "stacked_area":
        return make_stacked_area(panel_id, **args)
    if panel_kind == "stacked_bar":
        return make_stacked_bar(panel_id, **args)
    if panel_kind == "saved_search":
        return make_saved_search(panel_id, **args)
    raise ValueError(f"unknown panel kind: {panel_kind}")


def build_dashboard():
    panels_meta = []
    references = []
    for i, (suffix, kind, obj_type, args, w, h, x, y) in enumerate(PANELS):
        panel_id = f"thesis-cross-tool-{suffix}"
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
            "title": "Cross-Tool Correlation",
            "description": ("Demonstrează valoarea arhitecturii defense-in-depth: "
                            "Falco (runtime/syscall) + Suricata (network IDS) corelate "
                            "pe indexul unificat security-* prin câmpuri ECS canonice. "
                            "Insight cheie: node-2 este singurul nod cu vizibilitate cross-tool real "
                            "(Suricata systemd doar pe node-2, Falco DaemonSet pe toate nodurile)."),
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
    print("Ensuring security-ecs data view exists...")
    ensure_ecs_data_view()
    print("\nBuilding Cross-Tool Correlation dashboard...")
    build_dashboard()
    print("\nExporting NDJSON...")
    export_ndjson()
    print("\nDONE — open Kibana → Dashboards → 'Cross-Tool Correlation'")
    print(f"      URL: {KIBANA_URL}/app/dashboards#/view/{DASHBOARD_ID}")
