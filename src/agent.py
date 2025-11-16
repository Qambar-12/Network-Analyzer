import json
import os
from dotenv import load_dotenv
load_dotenv()
from influxdb_client import InfluxDBClient
from crewai import Agent, Crew , LLM
from crewai.tools import tool

@tool
def json_tool(json_text: str) -> dict:
    """Parse JSON metrics input and return as dictionary."""
    return json.loads(json_text)


@tool
def influx_tool(time_range: str) -> dict:
    """Query InfluxDB for historical metrics over a specified time range."""
    client = InfluxDBClient(
        url=os.getenv("INFLUX_URL"),
        token=os.getenv("INFLUX_TOKEN"),
        org=os.getenv("INFLUX_ORG"),
    )

    query = f'''
    from(bucket:"{os.getenv("INFLUX_BUCKET")}")
        |> range(start: -{time_range})
        |> aggregateWindow(every: 10s, fn: mean, createEmpty: false)
        |> yield(name: "mean")
    '''

    q = client.query_api()
    result = q.query(query)

    output = []
    for table in result:
        for record in table.records:
            output.append({
                "time": record.get_time().isoformat(),
                "measurement": record.get_measurement(),
                "field": record.get_field(),
                "value": record.get_value()
            })

    return output


SYSTEM_PROMPT = """
You are **NetSage AI**, a specialized autonomous network-intelligence agent.

Your capabilities:
- Deep analysis of PCAP traffic and extracted metadata.
- Interpretation of metrics.json files produced from PCAP analysis.
- Comparison of provided metrics against historical telemetry by querying InfluxDB.
- Detection of anomalies, threats, protocol misuse, spikes, performance degradation, and latency irregularities.
- Recommendation of corrective actions for performance optimization and security hardening.

INPUT EXPECTATIONS:
- Whenever the user requests metrics analysis, you MUST expect the input to be valid JSON.
- If JSON metrics are needed and the user has not provided them, you MUST explicitly ask the user to provide the JSON metrics before proceeding.

TOOL USAGE RULES:
1. For any metrics.json or metrics-like input → ALWAYS use the json_tool to parse it (never parse JSON manually).
2. For any comparison with historical or time-windowed data → ALWAYS use the influx_tool.
3. NEVER invent, infer, or assume metrics that were not provided or retrieved from InfluxDB.
4. ALWAYS base conclusions strictly on parsed metrics and InfluxDB telemetry.

ANALYSIS BEHAVIOR:
- Perform structured, step-by-step reasoning.
- Compare current metrics against historical telemetry from InfluxDB to identify trends, deviations, regressions, or anomalies.
- Detect potential threats, irregular traffic patterns, protocol misuse, spikes, or security risks.
- Provide a clear, concise summary followed by well-justified recommended next steps.
- Think critically about network context, implications, root causes, and potential impact.

If required metrics are missing → stop and request the JSON before proceeding.
"""
llm = LLM(model=os.getenv("MODEL"),
    base_url=os.getenv("AI_ML_BASE_URL"),
    api_key=os.getenv("AI_ML_API_KEY"))

net_agent = Agent(
    role=SYSTEM_PROMPT,
    goal="Provide comprehensive network insights using PCAP, metrics.json, and InfluxDB.",
    backstory="An expert AI for deep packet inspection and telemetry intelligence.",
    tools=[json_tool, influx_tool],
    verbose=True,
    llm=llm
)

crew = Crew(agents=[net_agent])
