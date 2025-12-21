# Copilot Instructions for Real-Time Attack Detection Project

## Overview
This project implements real-time network attack detection using Zeek for traffic analysis and a machine learning model (trained on UNSW-NB15) for classification.

## Architecture & Data Flow
- **Offline Training**: XGBoost classifier trained on UNSW-NB15 dataset (labeled network traffic with attack types: worms, malware, DoS, exploits)
- **Attack Simulation**: Real attack PCAPs from CIC-IDS2017 and Stratosphere Malware Captures are replayed using `tcpreplay` at real network speed
- **Live Monitoring**: Zeek monitors network interface in real-time, converting packets to structured flow logs (`conn.log` in JSON)
- **Real-time Detection**: `realtime_detector.py` tails Zeek logs, extracts features, and predicts attacks using the trained XGBoost model
- **Alerting**: When prediction confidence exceeds threshold, immediate alerts are raised with attack type and details
- **Model artifacts** are stored as a pipeline `.pkl` or as separate model/scaler/feature_order files

## Key Files & Directories
- `realtime_detector.py`: Real-time detection, Zeek log tailing, feature extraction, prediction.
- `train_unsw_nb15_detector.py`: Model/pipeline training and export.
- `unsw-nb15-cybersecurity-threat-detection-ann.ipynb`: Data exploration, preprocessing, and model training.
- `zeek-live/local.zeek`: Zeek config for JSON output and PCAP compatibility.
- `PCAP/`: Example PCAP files for testing.
- `Dataset/`: UNSW-NB15 CSVs and feature lists.

## Developer Workflows
- **Analyze a PCAP file (offline):**
  1. Run Zeek: `zeek -C -r <file.pcap> local.zeek`
  2. Run detector: `python realtime_detector.py --zeek-log zeek-live/conn.log --pipeline unsw_nb15_detector_pipeline_with_attack_cat_impute_zero.pkl`
  
- **Real-time attack simulation (recommended):**
  1. Start Zeek live: `sudo zeek -i <interface> local.zeek`
  2. Start detector: `python realtime_detector.py --zeek-log conn.log --pipeline <pipeline.pkl> --start-at-end`
  3. Replay attack: `sudo tcpreplay -i <interface> --mbps=10 <attack.pcap>`
  
- **Retrain model:** Use the notebook or `train_unsw_nb15_detector.py` to generate a new pipeline/model.

## Project-Specific Patterns
- Feature extraction is tailored to Zeek conn.log and UNSW-NB15 features.
- Both pipeline and classic (model/scaler/feature_order) modes are supported.
- Missing numerics default to 0, categoricals to "0".
- Class 0 or label "benign"/"normal" is treated as non-attack.

## Integration & Dependencies
- **Zeek** must be installed and accessible in PATH (for live capture, requires root/sudo)
- **tcpreplay** for replaying attack PCAPs at real network speed: `sudo apt install tcpreplay`
- **Python dependencies**: numpy, pandas, scikit-learn, joblib, xgboost (optionally tensorflow/keras)
- **Attack PCAP sources**: CIC-IDS2017, Stratosphere Malware Captures, or similar real attack datasets
- Model expects features in a specific order (see `feature_order.joblib` or pipeline)

## Conventions
- All Zeek logs must be in JSON format.
- Alert threshold is configurable via CLI (`--threshold`).
- Use joblib for model serialization when possible.

## Example Usage

**Offline analysis:**
```bash
zeek -C -r PCAP/arp-storm.pcap zeek-live/local.zeek
python realtime_detector.py --zeek-log zeek-live/conn.log --pipeline unsw_nb15_detector_pipeline_with_attack_cat_impute_zero.pkl
```

**Real-time simulation (3 terminals):**
```bash
# Terminal 1: Start Zeek live capture
sudo zeek -i eth0 zeek-live/local.zeek

# Terminal 2: Start real-time detector
python realtime_detector.py --zeek-log conn.log --pipeline unsw_nb15_detector_pipeline_with_attack_cat_impute_zero.pkl --start-at-end

# Terminal 3: Replay attack PCAP at real speed
sudo tcpreplay -i eth0 --mbps=10 PCAP/slammer.pcap
```

---
For new features, follow the established Zeek→feature extraction→ML prediction pipeline. See `realtime_detector.py` for extensibility patterns.
