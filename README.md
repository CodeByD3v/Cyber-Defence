# SOC Real-Time Attack Detection Platform

ML-powered Intrusion Detection System with real-time attack simulation and MITRE ATT&CK mapping.

## Features

- **Multi-class XGBoost Classifier** - Trained on UNSW-NB15 dataset (87.78% accuracy)
- **10 Attack Types**: Analysis, Backdoor, DoS, Exploits, Fuzzers, Generic, Normal, Reconnaissance, Shellcode, Worms
- **MITRE ATT&CK Mapping** - Automatic technique/tactic mapping for detected attacks
- **Explainability (XAI)** - Shows why each alert was flagged
- **Real-time Dashboard** - Live monitoring, analytics, and threat intelligence
- **Terminal Commands** - Full control via command-line interface

## Quick Start

### Prerequisites
- Python 3.8+
- UNSW-NB15 Dataset (place in `Dataset/` folder)

### Installation

```bash
# Clone the repository
git clone https://github.com/Aamod007/IDS.git
cd IDS

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r backend/requirements.txt

# Train the model (if not present)
python train_attack_classifier.py
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
| `/attack` | Simulate 10 random attacks |
| `/attack <type>` | Simulate 1 specific attack (dos, exploits, fuzzers, etc.) |
| `/attacks` | List available attack types with MITRE mappings |
| `/simulate <n>` | Simulate N random attacks (1-50) |
| `/help` | Show all commands |
| `/status` | Show system status |
| `/stats` | Show rolling statistics |
| `/clear` | Reset counters and alerts |
| `/export json` | Export alerts to JSON |
| `/export csv` | Export alerts to CSV |

## Architecture

```
├── backend/
│   ├── server.py          # WebSocket server
│   ├── simulator.py       # Attack simulation engine
│   ├── ml_inference.py    # ML model wrapper
│   ├── mitre.py           # MITRE ATT&CK mappings
│   ├── explainability.py  # XAI features
│   └── ...
├── model/
│   └── attack_classifier.joblib  # Trained XGBoost model
├── attack-detection-viz.html     # Frontend UI
├── train_attack_classifier.py    # Model training script
└── start_soc.bat                 # Windows launcher
```

## Model Details

- **Algorithm**: XGBoost Multi-class Classifier
- **Dataset**: UNSW-NB15 (2.5M records)
- **Features**: 42 network features (no data leakage)
- **Classes**: 10 attack categories
- **Accuracy**: 87.78%

## License

MIT
