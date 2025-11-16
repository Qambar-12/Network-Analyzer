import json
import os
from dotenv import load_dotenv

load_dotenv()

from influxdb_client import InfluxDBClient
from crewai import Agent, Crew, LLM, Task
from crewai.tools import tool


# ======================================================
# TOOLS
# ======================================================
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

    result = client.query_api().query(query)

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


# ======================================================
# SYSTEM PROMPT
# ======================================================
SYSTEM_PROMPT = """
You are **NetSage AI**, a specialized autonomous network-intelligence agent.

Your capabilities:
- Deep analysis of PCAP traffic and extracted metadata.
- Interpretation of metrics.json files produced from PCAP analysis.
- Comparison of provided metrics against historical telemetry by querying InfluxDB.
- Detection of anomalies, threats, protocol misuse, spikes, performance degradation, and latency irregularities.
- Recommendation of corrective actions for performance optimization and security hardening.

TOOL RULES:
1. For metrics JSON → ALWAYS use json_tool.
2. For historical comparisons → ALWAYS use influx_tool.
3. Never assume metrics that were not provided.

ANALYSIS REQUIREMENTS:
- Step-by-step, structured reasoning.
- Compare with historical InfluxDB data where relevant.
- Provide detailed analysis + clear next steps.
"""


# ======================================================
# LLM
# ======================================================
llm = LLM(
    model=os.getenv("MODEL"),
    base_url=os.getenv("AI_ML_BASE_URL"),
    api_key=os.getenv("AI_ML_API_KEY")
)


# ======================================================
# AGENT
# ======================================================
net_agent = Agent(
    role=SYSTEM_PROMPT,
    goal="Provide comprehensive network insights using PCAP, metrics.json, and InfluxDB.",
    backstory="An expert AI for deep packet inspection and telemetry intelligence.",
    tools=[json_tool, influx_tool],
    verbose=True,
    llm=llm
)


# ======================================================
# MAIN TASK (REQUIRED FOR CREWAI)
# ======================================================
main_task = Task(
    description=(
        "Analyze the user's network query or JSON metrics.\n\n"
        "User Input:\n{input}\n\n"
        "Provide a thorough, accurate, and structured analysis. "
        "Use tools where needed."
    ),
    expected_output="A detailed network analysis report.",
    agent=net_agent,
    inputs={"input"}   # <-- REQUIRED OR TASK GETS NO INPUT
)


# ======================================================
# CREW
# ======================================================
crew = Crew(
    agents=[net_agent],
    tasks=[main_task],
    verbose=True
)
