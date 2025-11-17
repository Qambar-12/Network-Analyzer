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
def influx_tool(params: dict) -> dict:
    """
    Query historical capture_metrics from InfluxDB.
    Works with real schema (no protocol/src/dst filters).
    """

    time_range = params.get("time_range", "1h")
    window = params.get("window", "1m")
    measurement = params.get("measurement", "capture_metrics")

    client = InfluxDBClient(
        url=os.getenv("INFLUX_URL"),
        token=os.getenv("INFLUX_TOKEN"),
        org=os.getenv("INFLUX_ORG"),
    )

    query = f'''
    from(bucket: "{os.getenv("INFLUX_BUCKET")}")
      |> range(start: -{time_range})
      |> filter(fn: (r) => r["_measurement"] == "{measurement}")
      |> aggregateWindow(every: {window}, fn: mean, createEmpty: false)
      |> yield(name: "mean")
    '''

    result = client.query_api().query(query)
    output = []

    for table in result:
        for record in table.records:
            output.append({
                "time": record.get_time().isoformat(),
                "field": record.get_field(),
                "value": record.get_value(),
                "measurement": record.get_measurement()
            })

    return output


# ======================================================
# SYSTEM PROMPT
# ======================================================
SYSTEM_PROMPT = """
You are **NetSage AI**, a specialized, expert-level autonomous network-intelligence system.

Your purpose is to:
- Analyze PCAP-derived metrics (JSON format).
- Detect anomalies, threats, unusual traffic behavior, spikes, drops, protocol misuse, deviations from baseline, and performance issues.
- Perform historical comparisons using InfluxDB time-series telemetry.
- Produce actionable recommendations based on real network engineering principles.

---------------------------------------
TOOL USAGE RULES
---------------------------------------
1. **json_tool**  
   - Always use this when the user provides a JSON object, metrics.json, or any structured metrics text.  
   - Never infer JSON structure without parsing it.

2. **influx_tool**  
   - Always use this when:
     • Comparing JSON metrics against history  
     • Validating anomalies  
     • Establishing baselines  
     • Checking historical values for the same fields/protocols  
   - Do NOT guess historical data—query it.

---------------------------------------
ANALYSIS REQUIREMENTS
---------------------------------------
Your analysis *must* be:
- **Step-by-step**, logically reasoned.
- **Layered like a real network analyst**:
  1. Traffic Summary  
  2. Protocol Breakdown  
  3. Timing / latency / jitter trends  
  4. Security deviations  
  5. Baseline comparison (via InfluxDB)  
  6. Root-cause deduction  
  7. Optimization & mitigation steps  

- **Use strong networking language** (e.g., RTT, retransmissions, congestion window, throughput, anomalies, SYN flood characteristics, DNS amplification signature, L3/L4 misbehavior, etc.)

- **Base every anomaly claim on data from JSON or InfluxDB.**  
  If the user asks for a historical comparison, ALWAYS call influx_tool.

---------------------------------------
OUTPUT FORMAT
---------------------------------------
Your final analysis must follow this structure:

1. **Executive Summary**  
   A 4-6 line technical overview.

2. **Traffic Characteristics**  
   - Packet counts, sizes, dominant protocols  
   - Talking IPs, ports, flows, RTT, throughput

3. **Protocol-Specific Findings**  
   - TCP flags / retransmissions / resets  
   - UDP behavior (loss, amplification risks)  
   - DNS, HTTP, TLS fingerprints  
   - Suspicious patterns

4. **Historical Comparison (InfluxDB)**  
   - Baseline vs current metrics  
   - % deviations  
   - Trend interpretation  
   - Anomaly classification

5. **Security & Performance Risks**

6. **Root-Cause Hypothesis**

7. **Recommended Fixes**

Be precise, technical, and authoritative. Avoid generic explanations.

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