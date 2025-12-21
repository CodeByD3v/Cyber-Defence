# SOC Real-Time Attack Detection Platform

ML-powered Intrusion Detection System with real-time attack simulation, Zeek PCAP analysis, and MITRE ATT&CK mapping.

## Features

- **Multi-class XGBoost Classifier** - Trained on UNSW-NB15 dataset (87.78% accuracy)
- **10 Attack Types**: Analysis, Backdoor, DoS, Exploits, Fuzzers, Generic, Normal, Reconnaissance, Shellcode, Worms
- **MITRE ATT&CK Mapping** - Automatic technique/tactic mapping for detected attacks
- **Zeek PCAP Analysis** - Process PCAP files through Zeek for ML-based detection
- **Explainability (XAI)** - Shows why each alert was flagged
- **Real-time Dashboard** - Live monitoring with VM simulation windows
- **Terminal Commands** - Full control via command-line interface

## Quick Start

### Prerequisites
- Python 3.8+
- UNSW-NB15 Dataset (place in `Dataset/` folder)
- Zeek (optional, for PCAP analysis - install in WSL on Windows)

### Installation

```bash
# Clone the repository
git clone https://github.com/Aamod007/EDA.git
cd EDA

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r backend/requirements.txt
```

### Running the Platform

```bash
# Start the server
python -m backend.server

# Or use the batch file (Windows)
start_soc.bat
```

Open http://127.0.0.1:8765 in your browser.

## Commands

| Command | Description |
|---------|-------------|
| `/attack` | Simulate random attacks from dataset |
| `/attack <type>` | Simulate specific attack (dos, exploits, recon, etc.) |
| `/attacks` | List available attack types with MITRE mappings |
| `/zeek pcap <file>` | Analyze PCAP file with Zeek + ML detection |
| `/zeek status` | Check Zeek status |
| `/help` | Show all commands |
| `/status` | Show system status |
| `/stats` | Show rolling statistics |
| `/clear` | Reset counters and alerts |
| `/export json` | Export alerts to JSON |
| `/export csv` | Export alerts to CSV |

## How Predictions Work

### Dataset Mode (`/attack`)
1. Loads samples from `Dataset/UNSW-NB15_*.csv` files with real IPs
2. Extracts 41 network features per sample
3. XGBoost model predicts attack type
4. Shows ML prediction vs ground truth comparison

### PCAP Mode (`/zeek pcap`)
1. Zeek processes PCAP file → generates `conn.log`
2. Pipeline maps Zeek fields to 41 UNSW-NB15 features
3. Same XGBoost model makes predictions
4. Results displayed in VM-style windows

### 41 Features Used
```
dur, proto, service, state, spkts, dpkts, sbytes, dbytes,
sttl, dttl, sload, dload, sloss, dloss, sinpkt, dinpkt,
sjit, djit, swin, dwin, stcpb, dtcpb, tcprtt, synack,
ackdat, smean, dmean, trans_depth, response_body_len,
ct_srv_src, ct_state_ttl, ct_dst_ltm, ct_src_dport_ltm,
ct_dst_sport_ltm, ct_dst_src_ltm, is_ftp_login, ct_ftp_cmd,
ct_flw_http_mthd, ct_src_ltm, ct_srv_dst, is_sm_ips_ports
```

## Architecture

```
├── backend/
│   ├── server.py          # WebSocket server
│   ├── simulator.py       # Attack simulation (dataset)
│   ├── pipeline.py        # Zeek log processing + ML
│   ├── ml_inference.py    # XGBoost model wrapper
│   ├── zeek_controller.py # Zeek process management
│   ├── mitre.py           # MITRE ATT&CK mappings
│   └── explainability.py  # XAI features
├── model/
│   └── attack_classifier.joblib  # Trained XGBoost model
├── Dataset/
│   └── UNSW-NB15_*.csv    # Training data with real IPs
├── PCAP/
│   └── *.pcap             # Sample PCAP files
├── attack-detection-viz.html     # Frontend UI
└── start_soc.bat                 # Windows launcher
```

## Model Details

- **Algorithm**: XGBoost Multi-class Classifier
- **Dataset**: UNSW-NB15 (2.5M records)
- **Features**: 41 network features
- **Classes**: 10 attack categories
- **Accuracy**: 87.78%
- **Alert Threshold**: 30% confidence

## Zeek Setup (Windows/WSL)

```bash
# In WSL
sudo apt update
sudo apt install zeek

# Or install from source
# Zeek should be at /opt/zeek/bin/zeek
```

## License

MIT
