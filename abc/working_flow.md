# DDoS Detection Simulator: Detailed Working Flow

The system is built around four main components running simultaneously: the **Simulator** (Attacker), the **Server** (Target), the **Detection Engine** (Guard), and the **Dashboard** (Monitor).

Here is a step-by-step working flow of how the system operates from the moment a packet is generated to the moment an alert appears on the dashboard.

---

### Phase 1: Traffic Generation (The Simulator)
*Script: `app/ddos_simulator.py`*

1. **Initiation**: The simulator is launched and begins generating HTTP/TCP traffic directed at the target server.
2. **Normal Traffic**: It continuously sends standard, legitimate HTTP GET requests to simulate normal user behavior.
3. **Attack Traffic**: When an attack is triggered (e.g., Hulk or Slowloris), the simulator spawns multiple threads to flood the server:
   - **Hulk Attack**: Sends a massive volume of rapid, randomized HTTP requests designed to exhaust server resources.
   - **Slowloris**: Opens numerous TCP connections and sends partial HTTP headers very slowly, keeping connections alive indefinitely to exhaust the server's connection pool.
   - **TCP Flood**: Rapidly opens and closes TCP connections.

### Phase 2: Traffic Reception (The Server)
*Script: `app/server.py`*

1. The lightweight Flask server runs on port `5050` and acts as the victim.
2. It processes incoming requests from the simulator. During a heavy attack, this server may struggle to respond, simulating a real-world DDoS impact.

### Phase 3: Packet Interception (The Detection Engine)
*Script: `app/detection.py`*

1. **Packet Capture**: The detection engine uses `pyshark` (a Python wrapper for TShark/Wireshark) to "sniff" the network interface.
2. **Filtering**: It applies a Berkeley Packet Filter (BPF) — `tcp port 5050` — to ignore irrelevant background traffic and only capture TCP packets heading to or from the target server.
3. **Callback Execution**: Every time a packet is captured, it is immediately passed to the `packet_callback` function for analysis.

### Phase 4: Feature Extraction (The Translator)
*Script: `app/feature_extraction.py`*

1. **Flow Tracking**: The system groups individual packets into "flows" based on a unique 4-tuple: `(Source IP, Destination IP, Source Port, Destination Port)`. 
2. **Mathematical Translation**: Raw packets cannot be fed directly into AI models. As packets arrive, the module calculates and updates **77 distinct numerical features** for that specific flow (matching the standard CICFlowMeter format). These include:
   - Total flow duration
   - Forward/Backward packet counts and byte sizes
   - Packet length statistics (mean, max, min, standard deviation)
   - Inter-arrival times (time between packets)
   - TCP flag counts (SYN, ACK, FIN, PSH, etc.)
   - Packet rates (packets per second, bytes per second)
3. **Throttling & Minimums**: 
   - A flow must accumulate at least **10 packets** before a prediction is attempted. (Flows with 1 or 2 packets don't have enough statistical data).
   - To prevent CPU overload during a massive flood, predictions are throttled and only run every 10 packets per flow.
4. **Stale Flow Reset**: If a flow is idle for more than 30 seconds, it is cleared from memory. This prevents recycled ports from inheriting old data and skewing rate calculations.

### Phase 5: Hybrid AI Prediction (The Brain)
*Script: `app/model_prediction.py`*

1. **Data Normalization**: The 77 features are normalized using a pre-trained Min-Max Scaler so all values fall within a standard range (e.g., 0 to 1).
2. **Ensemble Evaluation**: The features are passed through two pre-trained Machine Learning models:
   - **Random Forest (RF)**: Analyzes complex, non-linear patterns.
   - **Support Vector Machine (SVM)**: Checks which side of the mathematical "normal vs. attack" boundary the traffic falls on.
3. **Confidence Scoring**: Each model outputs a probability (0% to 100%) that the traffic is a DDoS attack. The system combines these using a weighted average (default: 60% RF, 40% SVM) to produce a **Final Hybrid Confidence Score**.

### Phase 6: Adaptive Thresholding (The Filter)
*Script: `app/adaptive_detection.py`*

1. **Baseline Tracking**: Instead of triggering an alert whenever confidence is >70%, the system maintains an Exponential Moving Average (EMA) of the overall traffic rate (packets per second).
2. **Spike Detection**: It compares the current traffic rate to the historical EMA baseline. If traffic suddenly spikes to >3x the normal baseline, the system recognizes anomalous volume.
3. **Dynamic Adjustment**: During a volume spike, the system temporarily **lowers** the required confidence threshold (e.g., from 70% down to 50%). This makes the AI more sensitive and aggressive during floods, while remaining strict during normal, quiet periods to prevent false positives.
4. **Final Verdict**: If the Hybrid Confidence Score exceeds the current Adaptive Threshold, the system officially declares a **DDoS ATTACK DETECTED**.

### Phase 7: Event Broadcasting
*Script: `app/logging_monitor.py`*

1. **Local Logging**: The prediction result, confidence scores, and current threshold are formatted and written to `logs/detection.log`.
2. **Redis Event Bus (Optional)**: If the Redis service is available (e.g., when running via Docker), the event is serialized as JSON and pushed to an in-memory Redis list. This acts as a high-speed bridge between the background detection engine and the frontend web dashboard.

### Phase 8: Real-Time Visualization (The Dashboard)
*Scripts: `app/dashboard.py` & `templates/dashboard.html`*

1. **Data Polling**: The user's web browser automatically polls the dashboard's `/api/data` endpoint every 2 seconds.
2. **Data Retrieval**:
   - The backend attempts to fetch the latest 20 events from Redis.
   - **Fallback Mechanism**: If Redis is unavailable or empty (e.g., running locally via standard Python scripts), the backend safely falls back to reading the last 500 lines of `logs/detection.log`, parsing the timestamps, confidence scores, and thresholds directly from the text.
3. **UI Update**: The frontend receives the JSON payload and updates the Chart.js graphs (Traffic Rate, Confidence History), the live event feed, and the main Status Ring (Green for Normal, Red for Attack) without requiring a page refresh.
