from fastapi import APIRouter, Query
from datetime import datetime, timedelta
from analyzer.core.influx_client import query_data

router = APIRouter(prefix="/metrics", tags=["Metrics"])

@router.get("/recent")
def get_recent_metrics(hours: int = 1):
    """Fetch metrics from the last X hours."""
    q = f'''
    from(bucket: "NetworkBucket")
      |> range(start: -{hours}h)
      |> filter(fn: (r) => r._measurement == "network_metrics")
      |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
      |> keep(columns: ["_time", "total_packets", "throughput_bps", "avg_pkt_size_bytes", "protocol_tcp", "protocol_udp"])
    '''
    data = query_data(q)
    return {"range": f"Last {hours} hour(s)", "data": data}


@router.get("/filter")
def filter_metrics(metric: str = Query(..., description="Metric field name, e.g. throughput_bps"),
                   min_value: float = 0.0):
    """Fetch metrics where a given field is above a threshold."""
    q = f'''
    from(bucket: "NetworkBucket")
      |> range(start: -6h)
      |> filter(fn: (r) => r._measurement == "network_metrics" and r._field == "{metric}" and r._value > {min_value})
    '''
    data = query_data(q)
    return {"filter": f"{metric} > {min_value}", "data": data}


@router.get("/top-talkers")
def get_top_talkers():
    """Get top talkers by source IP over the last hour."""
    q = '''
    from(bucket: "NetworkBucket")
      |> range(start: -1h)
      |> filter(fn: (r) => r._measurement == "network_metrics" and r._field == "top_talkers")
      |> last()
    '''
    data = query_data(q)
    return {"top_talkers": data}
