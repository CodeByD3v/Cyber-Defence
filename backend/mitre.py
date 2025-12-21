"""MITRE ATT&CK mapping for SOC behavior categories."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class MitreMapping:
    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str


# Mapping from behavior categories to MITRE ATT&CK
# Includes both pipeline behaviors and UNSW-NB15 attack categories
MITRE_MAPPING: dict[str, MitreMapping] = {
    # Pipeline behavior mappings
    "backdoor_like_c2": MitreMapping(
        technique_id="T1071",
        technique_name="Application Layer Protocol",
        tactic_id="TA0011",
        tactic_name="Command and Control",
    ),
    "reconnaissance": MitreMapping(
        technique_id="T1046",
        technique_name="Network Service Scanning",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
    ),
    "dos_ddos": MitreMapping(
        technique_id="T1498",
        technique_name="Network Denial of Service",
        tactic_id="TA0040",
        tactic_name="Impact",
    ),
    "worm_like": MitreMapping(
        technique_id="T1210",
        technique_name="Exploitation of Remote Services",
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
    ),
    "exploitation": MitreMapping(
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic_id="TA0001",
        tactic_name="Initial Access",
    ),
    "fuzzing": MitreMapping(
        technique_id="T1499",
        technique_name="Endpoint Denial of Service",
        tactic_id="TA0040",
        tactic_name="Impact",
    ),
    "malicious_unclassified": MitreMapping(
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        tactic_id="TA0002",
        tactic_name="Execution",
    ),
    # UNSW-NB15 attack category mappings
    "generic": MitreMapping(
        technique_id="T1595",
        technique_name="Active Scanning",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
    ),
    "exploits": MitreMapping(
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic_id="TA0001",
        tactic_name="Initial Access",
    ),
    "fuzzers": MitreMapping(
        technique_id="T1499",
        technique_name="Endpoint Denial of Service",
        tactic_id="TA0040",
        tactic_name="Impact",
    ),
    "dos": MitreMapping(
        technique_id="T1498",
        technique_name="Network Denial of Service",
        tactic_id="TA0040",
        tactic_name="Impact",
    ),
    "analysis": MitreMapping(
        technique_id="T1046",
        technique_name="Network Service Scanning",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
    ),
    "backdoor": MitreMapping(
        technique_id="T1071",
        technique_name="Application Layer Protocol",
        tactic_id="TA0011",
        tactic_name="Command and Control",
    ),
    "shellcode": MitreMapping(
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        tactic_id="TA0002",
        tactic_name="Execution",
    ),
    "worms": MitreMapping(
        technique_id="T1210",
        technique_name="Exploitation of Remote Services",
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
    ),
    "normal": MitreMapping(
        technique_id="T0000",
        technique_name="Benign Traffic",
        tactic_id="TA0000",
        tactic_name="None",
    ),
}


def get_mitre_mapping(behavior: str) -> Optional[MitreMapping]:
    """Look up MITRE ATT&CK mapping for a behavior category."""
    return MITRE_MAPPING.get(behavior.lower())


def get_mitre_dict(behavior: str) -> dict[str, str]:
    """Return MITRE mapping as a dict for JSON serialization."""
    mapping = get_mitre_mapping(behavior)
    if mapping is None:
        return {
            "technique_id": "T0000",
            "technique_name": "Unknown",
            "tactic_id": "TA0000",
            "tactic_name": "Unknown",
        }
    return {
        "technique_id": mapping.technique_id,
        "technique_name": mapping.technique_name,
        "tactic_id": mapping.tactic_id,
        "tactic_name": mapping.tactic_name,
    }
