# Network Analyzer

A comprehensive **network traffic capture, analysis, and visualization tool** built for real‑time network monitoring using **InfluxDB**, **Grafana**, and a modular Python backend. The system captures packets, extracts metrics, stores time‑series data, and visualizes it through rich dashboards. Designed for extensibility, automation, and machine learning‑based anomaly detection.

---

## 🚀 Features

### **1. Live Packet Capture**

* Capture traffic using Scapy
* Supports TCP, UDP, and ICMP protocols
* Automatic rotation & multi-file capture handling

### **2. Metrics Extraction**

* Extracts packet size, source/destination addresses, ports, protocols
* Computes aggregate metrics: throughput, protocol distribution, top talkers, etc.

### **3. Protocol Analysis**

* Identifies protocol usage patterns
* Flags unusual or suspicious protocol distributions

### **4. Time-Series Data Storage (InfluxDB)**

* Stores parsed network metrics under configurable bucket & organization
* Optimized schema for fast queries and Grafana visualization

### **5. Dashboards & Visualization (Grafana)**

* Bandwidth over time
* Protocol distribution (Pie Chart)
* Top source/destination IPs
* Packet count & size metrics
* Real-time refresh support

### **6. ML/AI Integration (Optional)**

* Uses AI/ML API endpoints for traffic anomaly detection
* Predictive models for emerging threats

---

## 🏗️ Project Structure

```
Network-Analyzer/
│
├── app.py                       # Streamlit UI
├── config_loader.py             # Loads YAML/ENV-based configurations
├── requirements.txt
│
├── src/
│   ├── capture/
│   │   ├── manager.py           # Handles packet capture flow
│   │   └── sniffer.py           # Scapy-powered packet sniffer
│   │
│   ├── analysis/
│   │   ├── metrics_extractor.py # Extracts metrics from packets
│   │   └── protocol_analyzer.py # Analyzes protocol behavior
│   │
│   ├── storage/
│   │   └── influx_client.py     # InfluxDB integration
│   │
│   └── utils/
│       └── helpers.py           # Utility functions
│
├── dashboards/                  # Grafana JSON models
├── scripts/                     # Automation or service scripts
└── README.md
```

---

## 🔧 Installation

### **1. Clone the repository**

```bash
git clone https://github.com/Qambar-12/Network-Analyzer.git
cd Network-Analyzer
```

### **2. Create & update `.env` file**

Copy example:

```bash
cp .env.example .env
```

Update required values:

```
INFLUX_URL=http://localhost:8086
INFLUX_TOKEN=your_token
INFLUX_ORG=your_org
INFLUX_BUCKET=network_metrics
GRAFANA_URL=http://localhost:3000
AI_ML_API_KEY=your_key
```

### **3. Install dependencies**

```bash
pip install -r requirements.txt
```

### **4. Start InfluxDB & Grafana**

Use Docker (recommended):

```bash
docker-compose up -d
```

---

## ▶️ Running the Application

Run the Streamlit interface:

```bash
streamlit run app.py
```

The UI provides:

* Start/stop capture
* Configure capture duration
* Trigger analysis
* Push results to InfluxDB
* Open Grafana dashboard link

---

## 📊 Grafana Visualization

Import dashboard JSON from the `/dashboards` directory.

### Example Protocol Distribution Pie Chart (Flux Query)

```flux
from(bucket: "network_metrics")
  |> range(start: -24h)
  |> filter(fn: (r) => r._measurement == "capture_packets")
  |> filter(fn: (r) => r._field == "size_bytes")
  |> group(columns: ["proto"])
  |> sum()
  |> group()
```

---

## 🧪 Testing

Run static and functional tests:

```bash
pytest
```

---

## 🛠️ Roadmap / Future Enhancements

* 🔐 Role-based access & API authentication
* 📈 ML-powered anomaly scoring
* 🌐 Websocket-based live updating dashboard
* 🚦 IPS/IDS rule recommendations
* 📦 Dockerized agent for distributed monitoring

---

## 🤝 Contributing

Pull requests are welcome!
For major changes, open an issue to discuss what you'd like to modify.

---

## 📜 License

This project is licensed under the **MIT License**.

---

## 🧑‍💻 Author

**Muhammad Qambar Hussain**

AI, Cybersecurity & Systems Engineering Student
