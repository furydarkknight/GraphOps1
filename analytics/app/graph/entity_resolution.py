"""
Entity Resolution Engine for GraphOps.
Resolves and merges multiple telemetry identifiers (hostname, IP address, MAC, agent_id, username, SID)
into canonical GraphNode entities.
"""

from typing import Dict, Optional, Set
import re


class EntityResolver:
    def __init__(self):
        # Maps alias -> canonical_id
        self._host_alias_map: Dict[str, str] = {}
        # Maps user alias -> canonical_id
        self._user_alias_map: Dict[str, str] = {}
        # Tracks canonical entities
        self._canonical_hosts: Set[str] = set()
        self._canonical_users: Set[str] = set()

    def normalize_hostname(self, name: str) -> str:
        if not name:
            return "unknown-host"
        cleaned = name.strip().lower()
        # Strip domain suffix if fully qualified e.g. web01.corp.internal -> web01
        cleaned = re.sub(r"\.(corp|internal|local|lan|domain)$", "", cleaned)
        return cleaned

    def normalize_username(self, name: str) -> str:
        if not name:
            return "unknown-user"
        cleaned = name.strip().lower()
        # Strip domain prefixes e.g. CORP\jdoe -> jdoe or jdoe@corp.internal -> jdoe
        if "\\" in cleaned:
            cleaned = cleaned.split("\\")[-1]
        if "@" in cleaned:
            cleaned = cleaned.split("@")[0]
        return cleaned

    def resolve_host(
        self,
        hostname: Optional[str] = None,
        ip: Optional[str] = None,
        agent_id: Optional[str] = None,
        mac: Optional[str] = None
    ) -> str:
        """
        Returns the resolved canonical host node ID.
        If an alias is already linked, reuses that canonical ID.
        """
        aliases = []
        if hostname:
            aliases.append(f"host:{self.normalize_hostname(hostname)}")
        if ip and not ip.startswith("127.") and ip != "::1":
            aliases.append(f"ip:{ip.strip()}")
        if agent_id:
            aliases.append(f"agent:{agent_id.strip().lower()}")
        if mac:
            aliases.append(f"mac:{mac.strip().lower()}")

        if not aliases:
            return "host:unresolved"

        # Check if any alias has an existing canonical mapping
        canonical_id: Optional[str] = None
        for alias in aliases:
            if alias in self._host_alias_map:
                canonical_id = self._host_alias_map[alias]
                break

        # If not found, use the best candidate as canonical
        if not canonical_id:
            if hostname:
                canonical_id = f"host:{self.normalize_hostname(hostname)}"
            elif agent_id:
                canonical_id = f"host:{agent_id.strip().lower()}"
            elif ip:
                canonical_id = f"host:{ip.strip()}"
            else:
                canonical_id = aliases[0]

        # Link all given aliases to this canonical ID
        for alias in aliases:
            self._host_alias_map[alias] = canonical_id

        return canonical_id

    def resolve_user(
        self,
        username: Optional[str] = None,
        email: Optional[str] = None,
        sid: Optional[str] = None
    ) -> str:
        """
        Returns resolved canonical user node ID.
        """
        aliases = []
        if username:
            aliases.append(f"user:{self.normalize_username(username)}")
        if email:
            aliases.append(f"user:{self.normalize_username(email)}")
        if sid:
            aliases.append(f"sid:{sid.strip()}")

        if not aliases:
            return "user:unresolved"

        canonical_id: Optional[str] = None
        for alias in aliases:
            if alias in self._user_alias_map:
                canonical_id = self._user_alias_map[alias]
                break

        if not canonical_id:
            canonical_id = f"user:{self.normalize_username(username or email or sid or 'unknown')}"

        for alias in aliases:
            self._user_alias_map[alias] = canonical_id

        return canonical_id
