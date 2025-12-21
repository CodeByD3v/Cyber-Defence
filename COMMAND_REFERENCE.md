# SOC Platform - Command Reference

## System Commands

| Command | Description |
|---------|-------------|
| `/help` | Show available commands |
| `/status` | System status (JSON) |
| `/stats` | Rolling statistics |
| `/clear` | Reset state |

## PCAP Analysis

| Command | Description |
|---------|-------------|
| `/zeek-pcap` | List available PCAP files |
| `/zeek-pcap <file>` | Process PCAP with Zeek |

**Example:**
```
/zeek-pcap slammer.pcap
```

## Attack Simulation (UNSW-NB15 Dataset)

| Command | Description |
|---------|-------------|
| `/attack` | Simulate 10 random attacks |
| `/attack <type>` | Simulate 1 specific attack |
| `/simulate <n>` | Simulate N random attacks (1-100) |
| `/attacks` | List available attack types |

**Attack Types:** analysis, backdoor, dos, exploits, fuzzers, generic, reconnaissance, shellcode, worms

**Examples:**
```
/attack dos
/attack exploits
/attack
```

## Export

| Command | Description |
|---------|-------------|
| `/export` | Export alerts as JSON |
| `/export csv` | Export alerts as CSV |

## Quick Start

1. Start the platform: `python -m backend.server` or `start_soc.bat`
2. Open browser: http://127.0.0.1:8765
3. Run `/attack` to simulate attacks
4. Run `/zeek-pcap slammer.pcap` to analyze real PCAP

## Requirements

- Python 3.8+
- WSL with Zeek (for PCAP analysis)
- UNSW-NB15 dataset in `Dataset/` folder
