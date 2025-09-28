# UKMDDoSDN v1.0

**DDoS Attack Dataset Generation Framework using Software-Defined Networking (SDN)**

A comprehensive framework for generating realistic cybersecurity datasets with both benign traffic and various DDoS attack patterns in a controlled enterprise network topology using Mininet network emulation and Ryu SDN controller.

## Features

- **Multi-Attack Dataset Generation**: Supports SYN flood, UDP flood, and ICMP flood attacks
- **Realistic Network Topology**: 4-subnet enterprise architecture with proper network isolation
- **Multiple Dataset Formats**: Generates 3 different CSV datasets with complementary features
- **SDN-Based Control**: Uses Ryu controller for intelligent traffic management and monitoring
- **High-Quality Labels**: Multi-class (0-3) and binary (0-1) classification labels
- **Scalable Architecture**: CPU optimization and multi-core support
- **Real-time Processing**: Live packet capture and feature extraction

## Architecture

### Network Topology
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   External      │    │   Corporate     │    │   Server/DMZ    │    │   Management    │
│   Network       │    │   Internal      │    │   Network       │    │   Network       │
│                 │    │                 │    │                 │    │                 │
│ h1: 192.168.10.x│    │h2-h5: 192.168.20.x│  │ h6: 192.168.30.x│    │ C0: 192.168.0.x │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Attack Types
- **Normal (0)**: Benign network traffic
- **SYN Flood (1)**: TCP SYN flood attacks
- **UDP Flood (2)**: UDP flooding attacks
- **ICMP Flood (3)**: ICMP ping flood attacks

### Generated Datasets
1. **packet_features.csv**: Packet-level dataset optimized for real-time detection
2. **flow_features.csv**: Flow-level statistical features from SDN controller
3. **cicflow_features.csv**: CICFlowMeter-based flow features

## Quick Start

### Prerequisites
- **Ubuntu 24.04.3** (recommended)
- **Root privileges** (required for Mininet)
- **Sufficient disk space** (datasets can be large)

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/nqmn/ukmddosdn.git
   cd ukmddosdn
   ```

2. **Run the automated setup**:
   ```bash
   sudo python3 setup.py
   ```

   This will install:
   - System packages (Mininet, Git, Python3, Curl, tshark, slowhttptest)
   - Ryu SDN controller (from GitHub)
   - CICFlowMeter (from GitHub)
   - All Python dependencies

   Dependencies will be installed in `ukmddosdn-suite/` subdirectory.


### Dataset Generation (Basic Usage)

**Single dataset generation**:
```bash
sudo python3 dataset_generation/main.py
```

**With custom configuration**:
```bash
sudo python3 dataset_generation/main.py config.json
```

**Bulk generation (multiple runs)** (preferable as this also will combine the datasets):
```bash
sudo python3 dataset_generation/run_bulk_main.py --runs 4 --config config.json
```

**With CPU optimization**:
```bash
sudo python3 dataset_generation/main.py --cores 4 --max-cores 16
```

## Project Structure

```
ukmddosdn/
├── README.md                           # This file
├── setup.py                           # Automated installation script
├── config.json                        # Default configuration
├── dataset_generation/
│   ├── main.py                        # Core orchestrator (2,404 lines)
│   ├── run_bulk_main.py              # Bulk generation script
│   ├── requirements.txt               # Python dependencies
│   ├── src/
│   │   ├── controller/               # Ryu-based SDN controller
│   │   ├── attacks/                  # DDoS attack implementations
│   │   ├── utils/                    # Utilities (logging, PCAP processing)
│   │   └── dataset_generator.py      # Dataset generation functions
│   └── files/                        # Feature definitions and mappings
├── output/                            # Generated datasets
└── ukmddosdn-suite/                   # External dependencies
    ├── README.md                      # Suite documentation
    ├── ryu/                          # Ryu SDN controller
    └── cicflowmeter/                 # CICFlowMeter tool
```

## Configuration

The framework uses `config.json` for scenario timing:

```json
{
    "scenario_durations":
    {
        "initialization": 5,
        "normal_traffic": 882,
        "syn_flood": 30,
        "udp_flood": 34,
        "icmp_flood": 130,
        "cooldown": 5
    }
}
```

## Output Datasets

### Dataset Features

**packet_features.csv**: Real-time packet-level features

**flow_features.csv**: SDN controller flow statistics

**cicflow_features.csv**: CICFlowMeter-based features

### Labels
- **Multi-class**: 0=normal, 1=syn_flood, 2=udp_flood, 3=icmp_flood
- **Binary**: 0=normal, 1=attack

## Requirements

### System Requirements
- **Ubuntu 24.04.3** (other versions may work but are untested)
- **Root privileges** (sudo access required)
- **4+ CPU cores** (recommended for optimal performance)
- **8+ GB RAM** (for large-scale dataset generation)
- **10+ GB disk space** (for datasets and dependencies)

### Key Dependencies
- **Mininet**: Network emulation framework
- **Ryu**: SDN controller framework
- **Scapy** (≥2.4.5): Packet manipulation and generation
- **CICFlowMeter**: Flow feature extraction
- **tshark**: Network protocol analyzer
- **slowhttptest**: HTTP DoS testing tool
- **Pandas/NumPy**: Data processing and analysis

## Important Notes

- **Always run with sudo**: Mininet requires root privileges for network namespace creation
- **Resource intensive**: Monitor system resources during generation
- **Network isolation**: Framework creates isolated virtual networks

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly with `sudo python3 setup.py`
5. Submit a pull request

## License

This project is released under MIT. See LICENSE file for details.

## Support

For issues, questions, or contributions:
- Create an issue in the repository
- Follow the troubleshooting guide above
- Ensure you're running on Ubuntu 24.04.3 with root privileges

## Related Projects

- **Ryu Controller**: https://github.com/nqmn/ryu
- **CICFlowMeter**: https://github.com/nqmn/cicflowmeter
- **Mininet**: http://mininet.org/

---

**UKMDDoSDN v1.0** - Advanced DDoS Dataset Generation for Cybersecurity Research