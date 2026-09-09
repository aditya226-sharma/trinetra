"""Module C — Relationship Graph from normalized unidirectional metadata
(PS26189).

Builds a small in-memory graph from UES events (laterally-movable entities:
IPs, users, processes, domains) and overlays Module A/B findings on top so the
dashboard and compliance flow can animate lateral movement and attacker paths.

Rows are derived from **metadata only** (no payload decryption):

  * ip → ip         communication (weight, protocols, threat flag)
  * user → ip       login attempts
  * user → proc     process execution
  * ip → domain     DNS resolution
  * threat → ip     module finding "flags" relationships

Exports a dashboard-ready JSON payload and can enumerate impacted assets.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

try:
    import networkx as nx  # type: ignore
except ImportError:  # pragma: no cover
    nx = None  # graph still degrades to dict ops via _edge_count

from schema import Event


KIND_PREFIX = {
    "ip": "ip",
    "domain": "domain",
    "user": "user",
    "proc": "proc",
    "threat": "threat",
}


class EntityGraph:
    """Relationship graph for one client workspace (keyed by ``client_id``)."""

    def __init__(self, client_id: str = "trinetra-core",
                 max_nodes: int = 5000, max_edges: int = 20000) -> None:
        self.client_id = client_id
        self.max_nodes = max_nodes
        self.max_edges = max_edges
        if nx is not None:
            self.graph = nx.MultiDiGraph()
        else:
            self.graph = None
        self._edge_counts: Dict[tuple, int] = {}  # ((src_id, dst_id, kind)) -> n
        self._edge_meta: Dict[tuple, Dict[str, Any]] = {}
        self._findings: List[Dict[str, Any]] = []

    # -- typed keys ----------------------------------------------------------
    @staticmethod
    def nid(kind: str, name: str) -> str:
        return f"{KIND_PREFIX.get(kind, 'misc')}:{name}"

    # -- ingestion -----------------------------------------------------------
    def add_event(self, event: Event) -> None:
        fields = event.fields
        src = str(fields.get("src_ip") or "")
        dst = str(fields.get("dst_ip") or "")
        domain = str(fields.get("dns_query") or "").strip()

        if nx is not None:
            if src:
                self.graph.add_node(src, kind="ip", label=src)
            if dst:
                self.graph.add_node(dst, kind="ip", label=dst)
            if domain:
                self.graph.add_node(self.nid("domain", domain), kind="domain", label=domain)
            if src and dst:
                self._bump_comm(src, dst, event)
            if src and domain:
                self._bump_edge(self.nid("domain", domain), src, "dns", {"domain": domain})
        self._consume_auth_and_exec(event, fields)

    def add_auth(self, event: Event) -> None:
        """Consume auth-style events (syslog sshd etc.)."""
        self._consume_auth_and_exec(event, event.fields)

    def _consume_auth_and_exec(self, event: Event, fields: Dict[str, Any]) -> None:
        user = str(fields.get("user") or "")
        proc = str(fields.get("proc") or fields.get("program") or "")
        host = str(fields.get("dst_ip") or fields.get("host") or fields.get("src_ip") or "")
        if not user and not proc:
            return
        if nx is None:
            return
        if user:
            self.graph.add_node(self.nid("user", user), kind="user", label=user)
            if host:
                self.graph.add_node(host, kind="ip", label=host)
                self._bump_edge(self.nid("user", user), host, "auth",
                                {"user": user, "result": fields.get("result", "attempt")})
        if proc:
            self.graph.add_node(self.nid("proc", proc), kind="proc", label=proc)
            if user:
                self._bump_edge(self.nid("user", user), self.nid("proc", proc), "exec",
                                {"proc": proc})
            if host:
                self._bump_edge(host, self.nid("proc", proc), "runs", {"proc": proc})

    def _bump_comm(self, src: str, dst: str, event: Event) -> None:
        key = (src, dst, "comm")
        proto = str(event.fields.get("proto") or "")
        self._edge_counts[key] = self._edge_counts.get(key, 0) + 1
        meta = self._edge_meta.setdefault(key, {"protop": set(), "flows": 0})
        meta["flows"] = meta.get("flows", 0) + 1
        if proto:
            meta["protop"].add(proto)
        self.graph.add_edge(src, dst, kind="comm", threat=0,
                            weight=self._edge_counts[key])

    def _bump_edge(self, a: str, b: str, kind: str, meta: Dict[str, Any]) -> None:
        key = (a, b, kind)
        self._edge_counts[key] = self._edge_counts.get(key, 0) + 1
        self._edge_meta.setdefault(key, meta)
        edge_key = self.graph.add_edge(a, b, kind=kind, threat=0,
                                       weight=self._edge_counts[key])
        if "result" in meta:
            self.graph[a][b][edge_key]["result"] = meta.get("result")

    # -- finding overlay -----------------------------------------------------
    def add_finding(self, finding: Dict[str, Any]) -> None:
        """Overlay a Module A/B finding; flags edges between involved entities."""
        threat_class = finding.get("threat_class") or "unknown"
        threat_id = self.nid("threat", threat_class)
        self._findings.append(finding)
        if nx is None:
            return
        self.graph.add_node(threat_id, kind="threat", label=threat_class,
                            severity=finding.get("severity", "high"))
        if "alert" in finding:
            finding = finding["alert"]
        src = finding.get("src")
        evidence = finding.get("evidence") or {}
        involved = []
        for key in ("src", "dst", "src_ip", "dst_ip"):
            val = evidence.get(key) or finding.get(key)
            if val and isinstance(val, str) and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", val):
                involved.append(val)
        for ip in involved:
            if not self.graph.has_node(ip):
                self.graph.add_node(ip, kind="ip", label=ip)
            if self.graph.has_edge(ip, threat_id):
                continue
            self.graph.add_edge(ip, threat_id, kind="flagged", threat=1, weight=1)
        # escalate threat=1 on comm edges that connect involved entities
        for u, v in zip(involved, involved[1:]):
            if self.graph.has_edge(u, v):
                for key in self.graph[u][v]:
                    self.graph[u][v][key]["threat"] = 1

    # -- queries -------------------------------------------------------------
    def threatened_ip_ids(self) -> List[str]:
        """Internal IPs linked to a threat node (impacted assets)."""
        if nx is None:
            return []
        threat_ids = [n for n, d in self.graph.nodes(data=True)
                      if d.get("kind") == "threat"]
        out = set()
        for t in threat_ids:
            for nbr in self.graph.predecessors(t):
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", str(nbr)):
                    out.add(nbr)
        return sorted(out)

    def communication_pairs(self, top: int = 50) -> List[Dict[str, Any]]:
        if nx is None:
            return []
        seen: Dict[tuple, int] = {}
        for u, v, k, d in self.graph.edges(keys=True, data=True):
            if d.get("kind") == "comm":
                seen[(u, v)] = max(seen.get((u, v), 0), d.get("weight", 1))
        edges = [{"src": u, "dst": v, "flows": w}
                 for (u, v), w in sorted(seen.items(),
                                         key=lambda kv: kv[1], reverse=True)]
        return edges[:top]

    def to_dashboard(self) -> Dict[str, Any]:
        """Dashboard-ready payload {nodes, edges, findings}."""
        if nx is None:
            return {"nodes": [], "edges": [], "findings": self._findings}
        palette = {"ip": "#4f46e5", "user": "#059669", "proc": "#d97706",
                   "domain": "#0891b2", "threat": "#dc2626"}
        nodes = [{
            "id": node_id,
            "label": data.get("label", node_id),
            "kind": data.get("kind", "misc"),
            "severity": data.get("severity", "none"),
            "color": palette.get(data.get("kind", "misc"), "#6b7280"),
        } for node_id, data in self.graph.nodes(data=True)]
        edges = [{
            "source": u, "target": v, "kind": d.get("kind", "comm"),
            "flows": d.get("weight", 1), "threat": d.get("threat", 0),
        } for u, v, k, d in self.graph.edges(keys=True, data=True)]
        return {"nodes": nodes, "edges": edges,
                "findings": self._findings, "client_id": self.client_id}

    def summary(self) -> Dict[str, Any]:
        return {
            "client_id": self.client_id,
            "nodes": len(self.graph.nodes) if nx else 0,
            "edges": len(self.graph.edges) if nx else 0,
            "comm_pairs": len(self.communication_pairs()),
            "threatened": self.threatened_ip_ids(),
            "findings": len(self._findings),
        }

    @staticmethod
    def to_json(graph) -> str:
        if nx is not None:
            return json.dumps(graph.to_dashboard(), default=str)
        return json.dumps(graph, default=str)