"""
GraphOps Security Graph Data Models & Schema.
Compliant with OCSF / ECS inspired entities for SOC graph analytics.
"""

from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
import datetime


class NodeType(str, Enum):
    HOST = "Host"
    USER = "User"
    SERVICE_ACCOUNT = "ServiceAccount"
    PROCESS = "Process"
    FILE = "File"
    IP = "IP"
    DOMAIN = "Domain"
    CLOUD_RESOURCE = "CloudResource"
    VULNERABILITY = "Vulnerability"
    GROUP = "Group"


class EdgeType(str, Enum):
    LOGGED_IN = "LOGGED_IN"
    SPAWNED = "SPAWNED"
    CONNECTED_TO = "CONNECTED_TO"
    MEMBER_OF = "MEMBER_OF"
    HAS_ADMIN = "HAS_ADMIN"
    TRUSTS = "TRUSTS"
    CAN_REACH = "CAN_REACH"
    EXPLOITABLE_VIA = "EXPLOITABLE_VIA"


class GraphNode(BaseModel):
    id: str = Field(..., description="Unique deterministic identifier for node")
    type: NodeType = Field(..., description="Node category / type")
    label: str = Field(..., description="Human readable label")
    criticality: int = Field(default=5, ge=1, le=10, description="Criticality score 1 to 10")
    is_crown_jewel: bool = Field(default=False, description="Whether node is a high-value crown jewel")
    properties: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary telemetry metadata")

    model_config = {"use_enum_values": True}


class GraphEdge(BaseModel):
    source: str = Field(..., description="Source node id")
    target: str = Field(..., description="Target node id")
    type: EdgeType = Field(..., description="Relationship type")
    timestamp: Optional[str] = Field(default=None, description="ISO timestamp of event occurrence")
    weight: float = Field(default=1.0, description="Edge weight / exploitability / confidence (0.0 to 1.0)")
    source_log: str = Field(default="sysmon", description="Telemetry log source (e.g. sysmon, zeek, cloudtrail, edr)")
    properties: Dict[str, Any] = Field(default_factory=dict, description="Metadata such as port, protocol, pid")

    model_config = {"use_enum_values": True}


class GraphSnapshotPayload(BaseModel):
    label: str = "GraphOps Snapshot"
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    window_start: Optional[str] = None
    window_end: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
