# UKMDDoSDN Dataset Generation (`main.py`)

This script orchestrates the end-to-end pipeline for generating the UKMDDoSDN v1.0 dataset. It boots a four-subnet Mininet topology, runs a Ryu L3 controller, replays benign and adversarial traffic (SYN/UDP/ICMP floods with enhanced features), captures per-phase PCAPs, and converts them into three labeled datasets: 30-feature packet dataset, flow statistics, and CICFlowMeter features.

## Key Capabilities
- Builds a 4-subnet enterprise topology (external, corporate, DMZ, and controller networks) with Mininet and an OpenFlow 1.3 switch.
- Launches `ryu-manager` with the bundled `src/controller/ryu_l3_router_app.py`, verifies the REST `/hello` endpoint, and checks the OpenFlow listener before continuing.
- Verifies dependencies upfront (`ryu-manager`, `mn`, `tshark`, `tcpdump`, `slowhttptest`, `taskset`) and exits with installation guidance if anything is missing.
- Runs normal background traffic via `src/gen_benign_traffic.py` and orchestrates multiple DDoS phases (enhanced SYN/UDP/ICMP floods).
- Captures phase-specific PCAPs (`normal.pcap`, `syn_flood.pcap`, etc.) and converts them into three datasets: 30-feature packet CSV, flow statistics CSV, and CICFlowMeter CSV with multi-class and binary labels using robust timestamp validation and per-phase timelines.
- Collects OpenFlow stats from the controller REST API and writes `flow_features.csv` with per-flow metrics aligned to the attack timeline.
- Generates CICFlowMeter-based flow features in `cicflow_features.csv` using the CICFlowMeter tool for comprehensive flow analysis.
- Applies optional CPU-affinity management (via `taskset`/`psutil`) and multiprocessing to accelerate PCAP post-processing.
- Generates rich logging, dataset summaries, timeline alignment scores, and cleanup actions for repeatable runs.

## Pipeline Overview
- Cleans residual Mininet state with `mn -c`, initializes structured logging, and prints a console banner.
- Loads scenario durations from the chosen config file and prepares `main_output/` for captures and logs.
- Starts the Ryu L3 router controller, waits for the OpenFlow port to come up, and probes the REST API.
- Builds the custom four-subnet Mininet topology, attaches the remote controller, waits for routing convergence, and runs `pingall` to confirm connectivity.
- For each scenario phase, launches `tcpdump` captures, updates the label timeline, and runs the corresponding benign or attack generator.
- Runs a background flow-stat collector polling `http://<controller_rest_host>:8080/flows` every 0.5 seconds to align controller metrics with the packet timeline.
- After traffic generation, processes every PCAP in parallel (with optional CPU affinity), merges them into three datasets: `packet_features.csv`, `flow_features.csv`, and `cicflow_features.csv`.
- Produces dataset summaries, timeline analysis, and finally tears down the controller and Mininet network.

## Traffic Phases
- `initialization`: buffer period before traffic starts.
- `normal_traffic`: benign baseline driven by `src/gen_benign_traffic.py`.
- `syn_flood`: enhanced SYN flood from h1 toward the server subnet (captured to `syn_flood.pcap`).
- `udp_flood`: enhanced UDP flood from h1 targeting port 53 on the server subnet (`udp_flood.pcap`).
- `icmp_flood`: enhanced ICMP flood from h1 to h4 with RFC1918 IP rotation (`icmp_flood.pcap`).
- `cooldown`: post-attack quiet period before cleanup.

## Attack Types
- **Enhanced SYN Flood** (`src/attacks/gen_syn_flood.py`):
  - High-intensity TCP SYN flood targeting server subnet (h1 → h6).
  - Randomized source IPs using RFC1918 private address ranges.
  - Configurable duration and intensity parameters.
  - Process monitoring and logging throughout execution.
- **Enhanced UDP Flood** (`src/attacks/gen_udp_flood.py`):
  - UDP flooding with port 53 targeting for DNS service disruption.
  - Randomized payload generation and source IP rotation.
  - High packet rate generation with process resource monitoring.
  - Targeting server subnet from external network simulation.
- **Enhanced ICMP Flood** (`src/attacks/enhanced_icmp_flood.py`):
  - ICMP ping flood with RFC1918 source IP rotation via `IPRotator` class.
  - Cross-subnet targeting (h1 → h4) for corporate network stress testing.
  - Protocol-correct ICMP packet generation with varying ID/sequence numbers.
  - Realistic TTL values and proper ICMP header construction.

## Flow Collection Guarantees & Error Handling
- The collector thread polls the controller every 0.5s, tagging each sample with phase-aligned labels and computing packet/byte rates for each entry.
- Each run emits a "Flow Capture Guarantee Report" in `main.log` summarizing polls attempted, success rate, unique flows, and timeout defaults (idle=30s, hard=300s).
- Empty polls append placeholder rows so downstream tooling still receives timeline-aligned records, and repeated empty polls are logged at debug level for diagnostics.
- REST request failures are caught; the collector logs the error, waits five seconds, and continues unless a shutdown event was triggered. A final warning is printed if no flow data was collected.
- Inspect `flow_features.csv` and the companion logs when investigating flow-processing anomalies or gaps in coverage.

## Configuration
Durations for each traffic phase are defined in `config.json`:
```json
{
    "scenario_durations": {
        "initialization": 5,
        "normal_traffic": 1600,
        "syn_flood": 88,
        "udp_flood": 176,
        "icmp_flood": 88,
        "cooldown": 5
    }
}
```
You can create alternative profiles and point the script to them with `--config`.

## Command-Line Arguments
- `config_file` (positional): configuration JSON to load (defaults to `config.json`).
- `--cores N`: worker processes for PCAP-to-CSV conversion (default `min(4, cpu_count())`).
- `--max-cores N`: upper bound used by the CPU affinity manager across subsystems (default 16).
- `--controller-ip IP`: address advertised to Mininet switches for OpenFlow (default `127.0.0.1`; use `192.168.0.1` for the management subnet).
- `--controller-port PORT`: OpenFlow TCP port (default 6653).
- `--controller-rest-host HOST`: host/IP for the REST polling client that calls `/hello` and `/flows` (default `localhost`).
- `--disable-cpu-affinity`: disable CPU pinning even if `taskset`/`psutil` are present.

## Prerequisites
- Linux host with root access (the script exits early if `os.geteuid() != 0`).
- System packages: `mininet`, `ryu-manager`, `tshark`, `tcpdump`, `slowhttptest`, `taskset`, plus `ss` or `netstat` for port checks.
- Python 3 environment with dependencies from `requirements.txt` (notably `scapy`, `pandas`, `requests`; `psutil` is optional but enables CPU affinity).
- Wireshark/TShark configured for non-interactive captures; ensure your user has the necessary permissions or run the entire script as root.

## Running the Script
1. Ensure no previous Mininet topology is running (`sudo mn -c`).
2. From the `dataset_generation` directory, execute (root required):
   ```bash
   sudo python3 main.py config.json --cores 4 --max-cores 16 --controller-ip 127.0.0.1 --controller-rest-host localhost
   ```
   Adjust flags as needed for your environment and CPU topology.

## Outputs and Reports
- PCAP captures per phase: `normal.pcap`, `syn_flood.pcap`, `udp_flood.pcap`, `icmp_flood.pcap`.
- **Three Dataset Types:**
  - Packet-level dataset: `packet_features.csv` (30 header-derived features plus multi-class and binary labels).
  - Flow-level dataset: `flow_features.csv` with derived rates and the synchronized label timeline.
  - CICFlow dataset: `cicflow_features.csv` with CICFlowMeter-based flow features and labels.
- Logs: `main.log`, `attack.log`, `ryu.log`, `mininet.log`, and per-process diagnostics from PCAP workers.
- Timeline analysis report and dataset summary emitted to the console and logs, including a quality score with optional detailed diagnostics if it falls below 70%.

## Operational Notes & Troubleshooting
- The run duration must cover every configured phase; shorten durations in the config file for quick smoke tests.
- The flow collector expects the REST app to expose `/flows` on port 8080. If the Ryu app is modified, ensure that endpoint remains available.
- CPU affinity requires both `taskset` and (optionally) `psutil`; missing components trigger warnings but the run continues without pinning.
- If PCAP post-processing reports empty results, inspect the corresponding worker logs under `main_output/` and confirm the traffic phase actually produced packets.
- All processes are terminated and Mininet is cleaned up automatically, but you can rerun `sudo mn -c` manually if a previous failure leaves residual state.

For further customization, inspect helper modules in `src/` (attacks, utils, controller app) to tweak traffic generation, feature extraction, or logging behavior.
