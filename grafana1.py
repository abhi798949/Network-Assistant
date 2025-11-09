import os
import json
import requests
from dotenv import load_dotenv

DEFAULT_BUCKET = os.environ.get("INFLUX_BUCKET", "SNMP")

def _headers(api_key: str):
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

def _resolve_influx_uid(grafana_url: str, api_key: str, preferred_name: str | None = None) -> str:
    """Resolve InfluxDB datasource UID"""
    env_uid = os.environ.get("GRAFANA_DATASOURCE_UID")
    if env_uid:
        return env_uid

    r = requests.get(f"{grafana_url}/api/datasources", headers=_headers(api_key), timeout=15)
    r.raise_for_status()
    datasources = r.json()
    for ds in datasources:
        if ds.get("type") == "influxdb" and (preferred_name is None or ds.get("name") == preferred_name):
            return ds["uid"]
    raise RuntimeError("No InfluxDB datasource found")

def create_comprehensive_dashboard(grafana_url: str, api_key: str, flux_bucket: str = DEFAULT_BUCKET):
    """Create a comprehensive network device dashboard with all metrics organized by category"""
    datasource_uid = _resolve_influx_uid(grafana_url, api_key)

    dashboard = {
        "dashboard": {
            "id": None,
            "uid": "network-device-dashboard",
            "title": "Network Monitoring - Comprehensive Dashboard",
            "tags": ["network", "devices", "monitoring", "snmp"],
            "timezone": "browser",
            "schemaVersion": 30,
            "version": 0,
            "panels": [
                # Row 1: Device Health Overview
                {
                    "id": 100,
                    "title": "Device Health",
                    "type": "row",
                    "gridPos": {"h": 1, "w": 24, "x": 0, "y": 0},
                    "collapsed": False
                },
                {
                    "id": 1,
                    "title": "Device Reachability",
                    "type": "stat",
                    "gridPos": {"h": 6, "w": 4, "x": 0, "y": 1},
                    "repeat": "device",
                    "repeatDirection": "h",
                    "maxPerRow": 4,
                    "targets": [
                        {
                            "refId": "A",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r["_measurement"] == "ping")
  |> filter(fn: (r) => r["device"] == "${{device}}")
  |> filter(fn: (r) => r["_field"] == "percent_packet_loss")
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)
  |> map(fn: (r) => ({{r with _value: if r._value == 0.0 then 1 else 0 }}))
  |> last()
'''
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "mappings": [
                                {
                                    "options": {
                                        "0": {"text": "DOWN", "color": "red", "index": 0},
                                        "1": {"text": "UP", "color": "green", "index": 1}
                                    },
                                    "type": "value"
                                }
                            ],
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "red", "value": None},
                                    {"color": "green", "value": 1}
                                ]
                            },
                            "color": {"mode": "thresholds"}
                        }
                    },
                    "options": {
                        "graphMode": "none",
                        "textMode": "value_and_name"
                    }
                },
                {
                    "id": 2,
                    "title": "CPU Usage",
                    "type": "gauge",
                    "gridPos": {"h": 6, "w": 5, "x": 4, "y": 1},
                    "repeat": "device",
                    "repeatDirection": "h",
                    "maxPerRow": 4,
                    "targets": [
                        {
                            "refId": "A",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
cisco_cpu = from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r["_measurement"] == "cpu")
  |> filter(fn: (r) => r["device"] == "${{device}}")
  |> filter(fn: (r) => r["_field"] == "cpu_1min")
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)
  |> group(columns: ["_time"])
  |> mean()
  |> map(fn: (r) => ({{r with _field: "cpu_usage"}}))

juniper_cpu = from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r["_measurement"] == "device")
  |> filter(fn: (r) => r["device"] == "${{device}}")
  |> filter(fn: (r) => r["_field"] == "cpu_usage")
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)
  |> map(fn: (r) => ({{r with _field: "cpu_usage"}}))

union(tables: [cisco_cpu, juniper_cpu])
  |> last()
'''
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "unit": "percent",
                            "min": 0,
                            "max": 100,
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "yellow", "value": 70},
                                    {"color": "red", "value": 90}
                                ]
                            }
                        }
                    },
                    "options": {
                        "showThresholdLabels": True,
                        "showThresholdMarkers": True
                    }
                },
                {
                    "id": 3,
                    "title": "Memory Usage",
                    "type": "gauge",
                    "gridPos": {"h": 6, "w": 5, "x": 9, "y": 1},
                    "repeat": "device",
                    "repeatDirection": "h",
                    "maxPerRow": 4,
                    "targets": [
                        {
                            "refId": "A",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
cisco_mem = from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r["_measurement"] == "memory")
  |> filter(fn: (r) => r["device"] == "${{device}}")
  |> filter(fn: (r) => r["_field"] == "mem_used" or r["_field"] == "mem_free")
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)
  |> group(columns: ["_time", "_field"])
  |> sum()
  |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
  |> map(fn: (r) => ({{ r with _value: if exists r.mem_used and exists r.mem_free and (r.mem_used + r.mem_free) > 0 then (r.mem_used / (r.mem_used + r.mem_free)) * 100.0 else 0.0, _field: "memory_used_percent" }}))
  |> keep(columns: ["_time", "_value", "_field", "device"])

juniper_mem = from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r["_measurement"] == "device")
  |> filter(fn: (r) => r["device"] == "${{device}}")
  |> filter(fn: (r) => r["_field"] == "memory_used_raw" or r["_field"] == "memory_total_raw")
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)
  |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
  |> map(fn: (r) => ({{ r with _value: if exists r.memory_total_raw and r.memory_total_raw > 0.0 then (r.memory_used_raw / r.memory_total_raw) * 100.0 else 0.0, _field: "memory_used_percent" }}))
  |> keep(columns: ["_time", "_value", "_field", "device"])

union(tables: [cisco_mem, juniper_mem])
  |> last()
'''
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "unit": "percent",
                            "min": 0,
                            "max": 100,
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "yellow", "value": 80},
                                    {"color": "red", "value": 95}
                                ]
                            }
                        }
                    },
                    "options": {
                        "showThresholdLabels": True,
                        "showThresholdMarkers": True
                    }
                },
                {
                    "id": 4,
                    "title": "CPU Trend (Last 24h)",
                    "type": "timeseries",
                    "gridPos": {"h": 6, "w": 10, "x": 14, "y": 1},
                    "targets": [
                        {
                            "refId": "A",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
cisco_cpu = from(bucket: "{flux_bucket}")
  |> range(start: -24h)
  |> filter(fn: (r) => r["_measurement"] == "cpu")
  |> filter(fn: (r) => r["device"] == "${{device}}")
  |> filter(fn: (r) => r["_field"] == "cpu_1min")
  |> aggregateWindow(every: 5m, fn: mean, createEmpty: false)
  |> group(columns: ["_time"])
  |> mean()
  |> map(fn: (r) => ({{r with _field: "cpu_usage"}}))

juniper_cpu = from(bucket: "{flux_bucket}")
  |> range(start: -24h)
  |> filter(fn: (r) => r["_measurement"] == "device")
  |> filter(fn: (r) => r["device"] == "${{device}}")
  |> filter(fn: (r) => r["_field"] == "cpu_usage")
  |> aggregateWindow(every: 5m, fn: mean, createEmpty: false)
  |> map(fn: (r) => ({{r with _field: "cpu_usage"}}))

union(tables: [cisco_cpu, juniper_cpu])
'''
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "unit": "percent",
                            "min": 0,
                            "max": 100,
                            "custom": {
                                "drawStyle": "line",
                                "lineWidth": 2,
                                "fillOpacity": 20,
                                "gradientMode": "hue"
                            },
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "yellow", "value": 70},
                                    {"color": "red", "value": 90}
                                ]
                            }
                        }
                    }
                },
                # Row 2: Interface Bandwidth & Traffic
                {
                    "id": 200,
                    "title": "Interface Bandwidth & Traffic",
                    "type": "row",
                    "gridPos": {"h": 1, "w": 24, "x": 0, "y": 7},
                    "collapsed": False
                },
                {
                    "id": 5,
                    "title": "Interface Traffic Rate (bps)",
                    "type": "timeseries",
                    "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8},
                    "repeat": "interface",
                    "repeatDirection": "h",
                    "maxPerRow": 4,
                    "targets": [
                        {
                            "refId": "A",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "interfaces")
  |> filter(fn: (r) => r.device == "${{device}}")
  |> filter(fn: (r) => r.ifDescr =~ /^${{interface:regex}}$/)
  |> filter(fn: (r) => r._field == "ifHCInOctets" or r._field == "ifHCOutOctets")
  |> pivot(rowKey: ["_time", "ifDescr"], columnKey: ["_field"], valueColumn: "_value")
  |> derivative(unit: 1s, nonNegative: true, columns: ["ifHCInOctets", "ifHCOutOctets"])
  |> map(fn: (r) => ({{ r with in_bps: r.ifHCInOctets * 8.0, out_bps: r.ifHCOutOctets * 8.0 }}))
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false, columns: ["in_bps", "out_bps"])
  |> keep(columns: ["_time", "in_bps", "out_bps", "ifDescr"])
'''
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "unit": "bps",
                            "custom": {
                                "drawStyle": "line",
                                "lineWidth": 1,
                                "fillOpacity": 10,
                                "gradientMode": "none",
                                "axisPlacement": "auto"
                            }
                        },
                        "overrides": [
                            {
                                "matcher": {"id": "byName", "options": "in_bps"},
                                "properties": [
                                    {"id": "color", "value": {"mode": "fixed", "fixedColor": "green"}},
                                    {"id": "displayName", "value": "Inbound - ${__field.labels.ifDescr}"}
                                ]
                            },
                            {
                                "matcher": {"id": "byName", "options": "out_bps"},
                                "properties": [
                                    {"id": "color", "value": {"mode": "fixed", "fixedColor": "blue"}},
                                    {"id": "displayName", "value": "Outbound - ${__field.labels.ifDescr}"}
                                ]
                            }
                        ]
                    },
                    "options": {
                        "tooltip": {"mode": "multi"},
                        "legend": {"displayMode": "table", "placement": "bottom", "calcs": ["mean", "max", "last"]}
                    }
                },
                {
                    "id": 6,
                    "title": "Interface Utilization (% of Speed)",
                    "type": "timeseries",
                    "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8},
                    "repeat": "interface",
                    "repeatDirection": "h",
                    "maxPerRow": 4,
                    "targets": [
                        {
                            "refId": "A",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "interfaces")
  |> filter(fn: (r) => r.device == "${{device}}")
  |> filter(fn: (r) => r.ifDescr =~ /^${{interface:regex}}$/)
  |> filter(fn: (r) => r._field == "ifHCInOctets" or r._field == "ifHighSpeed")
  |> pivot(rowKey: ["_time", "ifDescr"], columnKey: ["_field"], valueColumn: "_value")
  |> filter(fn: (r) => exists r.ifHCInOctets and exists r.ifHighSpeed)
  |> derivative(unit: 1s, nonNegative: true, columns: ["ifHCInOctets"])
  |> map(fn: (r) => ({{ r with _value: (r.ifHCInOctets * 8.0 / (r.ifHighSpeed * 1000000.0)) * 100.0 }}))
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)
'''
                        },
                        {
                            "refId": "B",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "interfaces")
  |> filter(fn: (r) => r.device == "${{device}}")
  |> filter(fn: (r) => r.ifDescr =~ /^${{interface:regex}}$/)
  |> filter(fn: (r) => r._field == "ifHCOutOctets" or r._field == "ifHighSpeed")
  |> pivot(rowKey: ["_time", "ifDescr"], columnKey: ["_field"], valueColumn: "_value")
  |> filter(fn: (r) => exists r.ifHCOutOctets and exists r.ifHighSpeed)
  |> derivative(unit: 1s, nonNegative: true, columns: ["ifHCOutOctets"])
  |> map(fn: (r) => ({{ r with _value: (r.ifHCOutOctets * 8.0 / (r.ifHighSpeed * 1000000.0)) * 100.0 }}))
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)
'''
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "unit": "percent",
                            "min": 0,
                            "max": 100,
                            "custom": {
                                "drawStyle": "line",
                                "lineWidth": 2,
                                "fillOpacity": 20,
                                "gradientMode": "none"
                            },
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "yellow", "value": 70},
                                    {"color": "red", "value": 90}
                                ]
                            }
                        },
                        "overrides": [
                            {
                                "matcher": {"id": "byFrameRefID", "options": "A"},
                                "properties": [
                                    {"id": "displayName", "value": "In Utilization - ${__field.labels.ifDescr}"},
                                    {"id": "color", "value": {"mode": "fixed", "fixedColor": "green"}}
                                ]
                            },
                            {
                                "matcher": {"id": "byFrameRefID", "options": "B"},
                                "properties": [
                                    {"id": "displayName", "value": "Out Utilization - ${__field.labels.ifDescr}"},
                                    {"id": "color", "value": {"mode": "fixed", "fixedColor": "blue"}}
                                ]
                            }
                        ]
                    },
                    "options": {
                        "tooltip": {"mode": "multi"},
                        "legend": {"displayMode": "table", "placement": "bottom", "calcs": ["mean", "max", "last"]}
                    }
                },
                # Row 3: Interface Errors & Discards
                {
                    "id": 300,
                    "title": "Interface Errors & Discards",
                    "type": "row",
                    "gridPos": {"h": 1, "w": 24, "x": 0, "y": 16},
                    "collapsed": False
                },
                {
                    "id": 7,
                    "title": "Interface Errors Rate",
                    "type": "timeseries",
                    "gridPos": {"h": 8, "w": 12, "x": 0, "y": 17},
                    "repeat": "interface",
                    "repeatDirection": "h",
                    "maxPerRow": 4,
                    "targets": [
                        {
                            "refId": "A",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "interfaces")
  |> filter(fn: (r) => r.device == "${{device}}")
  |> filter(fn: (r) => r.ifDescr =~ /^${{interface:regex}}$/)
  |> filter(fn: (r) => r._field == "ifInErrors")
  |> derivative(unit: 1s, nonNegative: true)
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)
'''
                        },
                        {
                            "refId": "B",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "interfaces")
  |> filter(fn: (r) => r.device == "${{device}}")
  |> filter(fn: (r) => r.ifDescr =~ /^${{interface:regex}}$/)
  |> filter(fn: (r) => r._field == "ifOutErrors")
  |> derivative(unit: 1s, nonNegative: true)
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)
'''
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "unit": "pps",
                            "custom": {
                                "drawStyle": "line",
                                "lineWidth": 1,
                                "fillOpacity": 10,
                                "gradientMode": "none"
                            },
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "yellow", "value": 1},
                                    {"color": "red", "value": 10}
                                ]
                            }
                        },
                        "overrides": [
                            {
                                "matcher": {"id": "byRegexp", "options": ".*ifInErrors.*"},
                                "properties": [
                                    {"id": "color", "value": {"mode": "fixed", "fixedColor": "orange"}},
                                    {"id": "displayName", "value": "In Errors - ${__field.labels.ifDescr}"}
                                ]
                            },
                            {
                                "matcher": {"id": "byRegexp", "options": ".*ifOutErrors.*"},
                                "properties": [
                                    {"id": "color", "value": {"mode": "fixed", "fixedColor": "red"}},
                                    {"id": "displayName", "value": "Out Errors - ${__field.labels.ifDescr}"}
                                ]
                            }
                        ]
                    },
                    "options": {
                        "tooltip": {"mode": "multi"},
                        "legend": {"displayMode": "table", "placement": "bottom", "calcs": ["mean", "sum", "last"]}
                    }
                },
                {
                    "id": 8,
                    "title": "Interface Discards Rate",
                    "type": "timeseries",
                    "gridPos": {"h": 8, "w": 12, "x": 12, "y": 17},
                    "repeat": "interface",
                    "repeatDirection": "h",
                    "maxPerRow": 4,
                    "targets": [
                        {
                            "refId": "A",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "interfaces")
  |> filter(fn: (r) => r.device == "${{device}}")
  |> filter(fn: (r) => r.ifDescr =~ /^${{interface:regex}}$/)
  |> filter(fn: (r) => r._field == "ifInDiscards")
  |> derivative(unit: 1s, nonNegative: true)
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)
'''
                        },
                        {
                            "refId": "B",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "interfaces")
  |> filter(fn: (r) => r.device == "${{device}}")
  |> filter(fn: (r) => r.ifDescr =~ /^${{interface:regex}}$/)
  |> filter(fn: (r) => r._field == "ifOutDiscards")
  |> derivative(unit: 1s, nonNegative: true)
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)
'''
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "unit": "pps",
                            "custom": {
                                "drawStyle": "line",
                                "lineWidth": 1,
                                "fillOpacity": 10,
                                "gradientMode": "none"
                            },
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "yellow", "value": 1},
                                    {"color": "red", "value": 10}
                                ]
                            }
                        },
                        "overrides": [
                            {
                                "matcher": {"id": "byRegexp", "options": ".*ifInDiscards.*"},
                                "properties": [
                                    {"id": "color", "value": {"mode": "fixed", "fixedColor": "purple"}},
                                    {"id": "displayName", "value": "In Discards - ${__field.labels.ifDescr}"}
                                ]
                            },
                            {
                                "matcher": {"id": "byRegexp", "options": ".*ifOutDiscards.*"},
                                "properties": [
                                    {"id": "color", "value": {"mode": "fixed", "fixedColor": "dark-purple"}},
                                    {"id": "displayName", "value": "Out Discards - ${__field.labels.ifDescr}"}
                                ]
                            }
                        ]
                    },
                    "options": {
                        "tooltip": {"mode": "multi"},
                        "legend": {"displayMode": "table", "placement": "bottom", "calcs": ["mean", "sum", "last"]}
                    }
                },
                # Row 4: Interface Status
                {
                    "id": 400,
                    "title": "Interface Status",
                    "type": "row",
                    "gridPos": {"h": 1, "w": 24, "x": 0, "y": 25},
                    "collapsed": False
                },
                {
                    "id": 9,
                    "title": "Interface Status Overview",
                    "type": "table",
                    "gridPos": {"h": 10, "w": 24, "x": 0, "y": 26},
                    "targets": [
                        {
                            "refId": "A",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: -1h)
  |> filter(fn: (r) => r._measurement == "interfaces")
  |> filter(fn: (r) => r.device == "${{device}}")
  |> group(columns: ["ifDescr"])
  |> last()
  |> keep(columns: ["_time", "ifDescr", "ifOperStatus", "ifAdminStatus", "ifHighSpeed"])
  |> map(fn: (r) => ({{r with operStatus: if r.ifOperStatus == 1 then "Up" else if r.ifOperStatus == 2 then "Down" else string(v: r.ifOperStatus)}}))
  |> map(fn: (r) => ({{r with adminStatus: if r.ifAdminStatus == 1 then "Up" else if r.ifAdminStatus == 2 then "Down" else string(v: r.ifAdminStatus)}}))
'''
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "custom": {
                                "align": "auto",
                                "width": 150
                            }
                        },
                        "overrides": [
                            {
                                "matcher": {"id": "byName", "options": "ifDescr"},
                                "properties": [{"id": "displayName", "value": "Interface"}]
                            },
                            {
                                "matcher": {"id": "byName", "options": "operStatus"},
                                "properties": [{"id": "displayName", "value": "Oper Status"}]
                            },
                            {
                                "matcher": {"id": "byName", "options": "adminStatus"},
                                "properties": [{"id": "displayName", "value": "Admin Status"}]
                            },
                            {
                                "matcher": {"id": "byName", "options": "ifHighSpeed"},
                                "properties": [{"id": "displayName", "value": "Speed (Mbps)"}, {"id": "unit", "value": "bps"}]
                            }
                        ]
                    },
                    "options": {
                        "showHeader": True,
                        "sortBy": [{"displayName": "Interface", "desc": False}]
                    }
                }
            ],
            "time": {
                "from": "now-1h",
                "to": "now"
            },
            "refresh": "30s",
            "templating": {
                "list": [
                    {
                        "name": "device",
                        "label": "Device",
                        "type": "query",
                        "datasource": {"uid": datasource_uid, "type": "influxdb"},
                        "query": f'''
import "influxdata/influxdb/schema"
schema.tagValues(
  bucket: "{flux_bucket}",
  tag: "device",
  predicate: (r) => r._measurement == "device" or r._measurement == "cpu",
  start: -24h
)
''',
                        "refresh": 1,
                        "includeAll": False,
                        "multi": False,
                        "current": {
                            "selected": False,
                            "text": "Select Device",
                            "value": ""
                        }
                    },
                    {
                        "name": "interface",
                        "label": "Interface",
                        "type": "query",
                        "datasource": {"uid": datasource_uid, "type": "influxdb"},
                        "query": f'''
import "influxdata/influxdb/schema"
schema.tagValues(
  bucket: "{flux_bucket}",
  tag: "ifDescr",
  predicate: (r) => r._measurement == "interfaces" and r.device == "${{device}}",
  start: -24h
)
''',
                        "refresh": 2,
                        "includeAll": True,
                        "multi": True,
                        "current": {
                            "selected": True,
                            "text": "All",
                            "value": "$__all"
                        },
                        "allValue": ".*"
                    }
                ]
            }
        },
        "overwrite": True,
        "message": "Comprehensive Network Device Dashboard - Organized by metric categories"
    }

    r = requests.post(
        f"{grafana_url}/api/dashboards/db",
        headers=_headers(api_key),
        data=json.dumps(dashboard),
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


def create_interface_summary_dashboard(grafana_url: str, api_key: str, flux_bucket: str = DEFAULT_BUCKET):
    """Create a high-level interface summary dashboard with key metrics"""
    datasource_uid = _resolve_influx_uid(grafana_url, api_key)

    dashboard = {
        "dashboard": {
            "id": None,
            "uid": "interface-metrics-dashboard",
            "title": "Interface Summary Dashboard",
            "tags": ["network", "interfaces", "summary"],
            "timezone": "browser",
            "schemaVersion": 30,
            "version": 0,
            "panels": [
                # Top Interfaces by Utilization
                {
                    "id": 1,
                    "title": "Top 10 Interfaces by Utilization",
                    "type": "bargauge",
                    "gridPos": {"h": 10, "w": 12, "x": 0, "y": 0},
                    "repeat": "interface",
                    "repeatDirection": "h",
                    "maxPerRow": 4,
                    "targets": [
                        {
                            "refId": "A",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "interfaces")
  |> filter(fn: (r) => r.device == "${{device}}")
  |> filter(fn: (r) => r._field == "ifHCInOctets" or r._field == "ifHighSpeed" or r._field == "ifOperStatus")
  |> pivot(rowKey: ["_time", "ifDescr"], columnKey: ["_field"], valueColumn: "_value")
  |> filter(fn: (r) => r.ifOperStatus == 1)
  |> derivative(unit: 1s, nonNegative: true, columns: ["ifHCInOctets"])
  |> map(fn: (r) => ({{ r with _value: (r.ifHCInOctets * 8.0 / (r.ifHighSpeed * 1000000.0)) * 100.0, metric: "In Utilization" }}))
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)
  |> group(columns: ["ifDescr", "device", "metric"])
  |> max()
  |> group()
  |> sort(columns: ["_value"], desc: true)
  |> limit(n: 10)
  |> map(fn: (r) => ({{ r with _value: r._value, _field: r.metric, ifDescr: r.ifDescr }}))
'''
                        },
                        {
                            "refId": "B",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "interfaces")
  |> filter(fn: (r) => r.device == "${{device}}")
  |> filter(fn: (r) => r._field == "ifHCOutOctets" or r._field == "ifHighSpeed" or r._field == "ifOperStatus")
  |> pivot(rowKey: ["_time", "ifDescr"], columnKey: ["_field"], valueColumn: "_value")
  |> filter(fn: (r) => r.ifOperStatus == 1)
  |> derivative(unit: 1s, nonNegative: true, columns: ["ifHCOutOctets"])
  |> map(fn: (r) => ({{ r with _value: (r.ifHCOutOctets * 8.0 / (r.ifHighSpeed * 1000000.0)) * 100.0, metric: "Out Utilization" }}))
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)
  |> group(columns: ["ifDescr", "device", "metric"])
  |> max()
  |> group()
  |> sort(columns: ["_value"], desc: true)
  |> limit(n: 10)
  |> map(fn: (r) => ({{ r with _value: r._value, _field: r.metric, ifDescr: r.ifDescr }}))
'''
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "unit": "percent",
                            "min": 0,
                            "max": 100,
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "yellow", "value": 70},
                                    {"color": "red", "value": 90}
                                ]
                            },
                            "displayName": "${__field.labels.ifDescr} - ${__field.labels.metric}"
                        }
                    },
                    "overrides": [
                        {
                            "matcher": {"id": "byFrameRefID", "options": "A"},
                            "properties": [
                                {"id": "color", "value": {"mode": "fixed", "fixedColor": "green"}}
                            ]
                        },
                        {
                            "matcher": {"id": "byFrameRefID", "options": "B"},
                            "properties": [
                                {"id": "color", "value": {"mode": "fixed", "fixedColor": "blue"}}
                            ]
                        }
                    ],
                    "options": {
                        "orientation": "horizontal",
                        "displayMode": "gradient",
                        "showUnfilled": True,
                        "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}
                    }
                },
                # Interface Health Matrix
                {
                    "id": 2,
                    "title": "Interface Health Matrix",
                    "type": "state-timeline",
                    "gridPos": {"h": 10, "w": 12, "x": 12, "y": 0},
                    "repeat": "interface",
                    "repeatDirection": "h",
                    "maxPerRow": 4,
                    "targets": [
                        {
                            "refId": "A",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "interfaces")
  |> filter(fn: (r) => r.device == "${{device}}")
  |> filter(fn: (r) => r.ifDescr =~ /^${{interface:regex}}$/)
  |> filter(fn: (r) => r._field == "ifOperStatus")
  |> aggregateWindow(every: v.windowPeriod, fn: last, createEmpty: false)
'''
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "mappings": [
                                {
                                    "type": "value",
                                    "options": {
                                        "1": {"text": "Up", "color": "green"},
                                        "2": {"text": "Down", "color": "red"},
                                        "3": {"text": "Testing", "color": "yellow"},
                                        "4": {"text": "Unknown", "color": "gray"},
                                        "5": {"text": "Dormant", "color": "orange"},
                                        "6": {"text": "NotPresent", "color": "gray"},
                                        "7": {"text": "LowerLayerDown", "color": "red"}
                                    }
                                }
                            ]
                        }
                    }
                },
                # Total Bandwidth Usage
                {
                    "id": 3,
                    "title": "Total Network Bandwidth (All Interfaces)",
                    "type": "timeseries",
                    "gridPos": {"h": 8, "w": 24, "x": 0, "y": 10},
                    "repeat": "interface",
                    "repeatDirection": "h",
                    "maxPerRow": 4,
                    "targets": [
                        {
                            "refId": "A",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "interfaces")
  |> filter(fn: (r) => r.device == "${{device}}")
  |> filter(fn: (r) => r._field == "ifHCInOctets")
  |> derivative(unit: 1s, nonNegative: true)
  |> map(fn: (r) => ({{ r with _value: r._value * 8.0 }}))
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)
  |> group()
  |> sum()
'''
                        },
                        {
                            "refId": "B",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "interfaces")
  |> filter(fn: (r) => r.device == "${{device}}")
  |> filter(fn: (r) => r._field == "ifHCOutOctets")
  |> derivative(unit: 1s, nonNegative: true)
  |> map(fn: (r) => ({{ r with _value: r._value * 8.0 }}))
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)
  |> group()
  |> sum()
'''
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "unit": "bps",
                            "custom": {
                                "drawStyle": "line",
                                "lineWidth": 2,
                                "fillOpacity": 20,
                                "gradientMode": "hue"
                            }
                        },
                        "overrides": [
                            {
                                "matcher": {"id": "byFrameRefID", "options": "A"},
                                "properties": [
                                    {"id": "displayName", "value": "Total Inbound"},
                                    {"id": "color", "value": {"mode": "fixed", "fixedColor": "green"}}
                                ]
                            },
                            {
                                "matcher": {"id": "byFrameRefID", "options": "B"},
                                "properties": [
                                    {"id": "displayName", "value": "Total Outbound"},
                                    {"id": "color", "value": {"mode": "fixed", "fixedColor": "blue"}}
                                ]
                            }
                        ]
                    },
                    "options": {
                        "tooltip": {"mode": "multi"},
                        "legend": {"displayMode": "list", "placement": "bottom", "calcs": ["mean", "max"]}
                    }
                },
                # Error Summary
                {
                    "id": 4,
                    "title": "Total Errors & Discards (All Interfaces)",
                    "type": "stat",
                    "gridPos": {"h": 6, "w": 24, "x": 0, "y": 18},
                    "repeat": "interface",
                    "repeatDirection": "h",
                    "maxPerRow": 4,
                    "targets": [
                        {
                            "refId": "A",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "interfaces")
  |> filter(fn: (r) => r.device == "${{device}}")
  |> filter(fn: (r) => r._field == "ifInErrors" or r._field == "ifOutErrors")
  |> group()
  |> sum()
'''
                        },
                        {
                            "refId": "B",
                            "datasource": {"uid": datasource_uid, "type": "influxdb"},
                            "query": f'''
from(bucket: "{flux_bucket}")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "interfaces")
  |> filter(fn: (r) => r.device == "${{device}}")
  |> filter(fn: (r) => r._field == "ifInDiscards" or r._field == "ifOutDiscards")
  |> group()
  |> sum()
'''
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "yellow", "value": 100},
                                    {"color": "red", "value": 1000}
                                ]
                            },
                            "color": {"mode": "thresholds"}
                        },
                        "overrides": [
                            {
                                "matcher": {"id": "byFrameRefID", "options": "A"},
                                "properties": [
                                    {"id": "displayName", "value": "Total Errors"}
                                ]
                            },
                            {
                                "matcher": {"id": "byFrameRefID", "options": "B"},
                                "properties": [
                                    {"id": "displayName", "value": "Total Discards"}
                                ]
                            }
                        ]
                    },
                    "options": {
                        "graphMode": "area",
                        "textMode": "value_and_name",
                        "colorMode": "background"
                    }
                }
            ],
            "time": {
                "from": "now-6h",
                "to": "now"
            },
            "refresh": "1m",
            "templating": {
                "list": [
                    {
                        "name": "device",
                        "label": "Device",
                        "type": "query",
                        "datasource": {"uid": datasource_uid, "type": "influxdb"},
                        "query": f'''
import "influxdata/influxdb/schema"
schema.tagValues(
  bucket: "{flux_bucket}",
  tag: "device",
  predicate: (r) => r._measurement == "interfaces",
  start: -24h
)
''',
                        "refresh": 1,
                        "includeAll": False,
                        "multi": False,
                        "current": {
                            "selected": False,
                            "text": "Select Device",
                            "value": ""
                        }
                    }
                ]
            }
        },
        "overwrite": True,
        "message": "Interface Summary Dashboard with aggregated metrics"
    }

    r = requests.post(
        f"{grafana_url}/api/dashboards/db",
        headers=_headers(api_key),
        data=json.dumps(dashboard),
        timeout=30,
    )
    r.raise_for_status()
    return r.json()