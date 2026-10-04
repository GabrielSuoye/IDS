# 🛡️ Hybrid 3-Tier Intrusion Detection System (IDS)

A high-performance, asynchronous, multi-processed Network Intrusion Detection System (IDS) written in Python using **Scapy**, **XGBoost**, and **PyTorch**. 

This system uses a **cooperative, tiered defense-in-depth architecture** to process packets at sub-millisecond speeds. High-volume packet capture and time-series feature extraction happen on an asynchronous event loop, while heavy Machine Learning and Deep Learning inference are safely offloaded to an isolated CPU process pool to completely bypass Python's Global Interpreter Lock (GIL).

---

## 🏗️ System Architecture

Traffic moves down a conditional cascade to maximize throughput and minimize computational overhead:

1. **Tier 1: Deterministic Engine (O(1) Signature Matching)**
   * Catches known malicious threats instantly inside the main async thread using fast hash-set lookups for blocklisted IPs and prohibited ports. Skips advanced evaluation if a match is found.
2. **Tier 2: Supervised ML Core (XGBoost Classifier)**
   * Evaluates rolling time-series features (packets/sec, unique destination counts, average lengths) using a pre-trained **XGBoost** model to classify known attack footprints like volumetric **DDoS** or **Port Scans**.
3. **Tier 3: Unsupervised Deep Learning Core (PyTorch Autoencoder)**
   * If Tier 2 marks traffic as "Normal," it falls back to a **Neural Network Autoencoder**. It evaluates reconstruction loss to flag never-before-seen anomalies and structural **Zero-Day** threats.

---

## 📁 Project Structure

```text
IDS/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── logs/                      # Automatically created on host to store alerts
│   └── ids_alerts.jsonl
└── src/
    ├── monitor.py             # Main async ingestion pipeline & IDS engine
    └── data/
        └── xgboost_ids.pkl    # Pre-trained Tier 2 ML model
```

---

## 🚀 Deployment Guide (Linux Servers)

This IDS is optimized for native deployment on Linux-based production servers or within network probes attached to Windows Active Directory domains.

### 📋 Prerequisites
Ensure you have **Docker** and **Docker Compose** installed on your server.

### 1. Build and Start the IDS
From your root `~/IDS` directory, launch the entire containerized pipeline in the background:
```bash
sudo docker compose up -d --build
```

### 2. View Live Streaming Alerts
Monitor real-time detections and multi-tier triggers as they hit your interfaces:
```bash
sudo docker compose logs -f
```

### 3. Access Persistent Logs
All triggered anomalies are written as non-blocking `JSON Lines` straight to your host machine's directory for simple downstream ingestion (SIEM/ELK):
```bash
cat logs/ids_alerts.jsonl
```

### 4. Stop the IDS
```bash
sudo docker compose down
```

---

## 🪟 Windows Deployment Workaround

> ⚠️ **Important Node for Windows Testing:** Docker Desktop on Windows routes networking inside a virtual abstraction layer (WSL2/Hyper-V). As a result, Docker's native `network_mode: "host"` flag cannot capture your host hardware's raw network traffic inside a container on Windows. 

If running or testing on a physical Windows host machine (such as a workspace laptop), deploy the script **natively** instead:

1. Install **Python 3.11+** and **Npcap** (the standard Windows packet capture driver, typically bundled with Wireshark).
2. Open an **Administrator PowerShell / Command Prompt**.
3. Navigate to your project directory and run:
   ```powershell
   pip install -r requirements.txt
   python src/monitor.py
   ```

---

## ⚙️ Configuration & Fine-Tuning

You can modify configurations directly inside the code or setup files:
* **Change Sniffing Interface:** Update the `IDS_INTERFACE` environment variable inside `docker-compose.yml` to match your active target adapter (e.g., `eth0`, `wlan0`, `en0`).
* **Update Signature Rules:** Add known malicious endpoints or restricted system endpoints directly to `self.blocklisted_ips` and `self.restricted_ports` in `src/monitor.py` for immediate O(1) dropping.

