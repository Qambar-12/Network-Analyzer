import os
import json
import scapy.all as scapy
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

from influxdb_client import InfluxDBClient
from langchain.chat_models import ChatOpenAI
from langchain.agents import initialize_agent, AgentType
from langchain.tools import tool



# ================================
# SYSTEM PROMPT
# ================================
SYSTEM_PROMPT = """
You are **NetSage AI**, an autonomous network analysis agent.

Your responsibilities:
- Analyze PCAP traffic and provide protocol-level insights.
- Interpret and summarize JSON metrics produced by the analytics engine.
- Query the InfluxDB time-series database for time-windowed network telemetry.
- Detect anomalies, threats, and suspicious patterns.
- Provide optimization suggestions for performance and stability.
- If the user uploads PCAP/JSON or asks questions about the network state, you MUST use the appropriate TOOL instead of guessing.

TOOL USAGE RULES:
1. If the question requires real data (pcap, json, influx), always call a TOOL.
2. NEVER fabricate or hallucinate metrics, timestamps, IPs, protocols, or statistics.
3. After receiving tool output, analyze it step-by-step and give clear insights.
4. Ask for more data if needed.

TOOLS YOU MAY CALL:
- parse_json_metrics(json_text)
- influx_query(time_range)

Be proactive, factual, and detailed in your explanations.
"""


# ================================
# TOOL DEFINITIONS
# ================================

class NetTools:


    # ---- Tool 1: JSON metrics parser -----------------------------------
    @tool("parse_json_metrics")
    def parse_json_metrics(json_text: str) -> dict:
        """Parse and return a metrics.json file content."""
        return json.loads(json_text)

    # ---- Tool 2: InfluxDB time-series query -----------------------------
    @tool("influx_query")
    def influx_query(time_range: str) -> dict:
        """
        Query InfluxDB for recorded metrics over a given time window.
        Example time_range: "10m", "1h", "24h"
        """

        client = InfluxDBClient(
            url=os.getenv("INFLUX_URL"),
            token=os.getenv("INFLUX_TOKEN"),
            org=os.getenv("INFLUX_ORG"),
        )
        q = client.query_api()

        flux = f'''
        from(bucket: "{os.getenv("INFLUX_BUCKET")}")
            |> range(start: -{time_range})
            |> aggregateWindow(every: 10s, fn: mean, createEmpty: false)
            |> yield(name: "mean")
        '''
        try:
            result = q.query(flux)
            final = []

            for table in result:
                for record in table.records:
                    final.append({
                        "time": record.get_time().isoformat(),
                        "measurement": record.get_measurement(),
                        "field": record.get_field(),
                        "value": record.get_value(),
                    })

            return {"status": "ok", "records": final}

        except Exception as e:
            return {"status": "error", "message": str(e)}



# ================================
# AGENT INITIALIZER
# ================================

def create_agent():
    llm = ChatOpenAI(
        model_name=os.getenv("MODEL"),
        client_kwargs={"api_key": os.getenv("AI_ML_API_KEY"),"base_url": os.getenv("AI_ML_BASE_URL")},
        temperature=0.2
    )

    tools = [
        NetTools.extract_metrics_from_pcap,
        NetTools.parse_json_metrics,
        NetTools.influx_query
    ]

    agent = initialize_agent(
        tools,
        llm,
        agent=AgentType.OPENAI_FUNCTIONS,  # enables automatic tool selection
        verbose=True,
        handle_parsing_errors=True
    )

    agent.system_message = SYSTEM_PROMPT
    return agent
