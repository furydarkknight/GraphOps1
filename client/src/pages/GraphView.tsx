import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { GraphCanvas } from "../components/GraphCanvas";
import { NodeDrawer } from "../components/NodeDrawer";
import { BlastRadiusPanel } from "../components/BlastRadiusPanel";
import { AttackPathView } from "../components/AttackPathView";
import { Network, Zap, Crosshair, Filter } from "lucide-react";

export function GraphView() {
  const [snapshots, setSnapshots] = useState<any[]>([]);
  const [selectedSnapshotId, setSelectedSnapshotId] = useState<string>("");
  const [graphData, setGraphData] = useState<any>({ nodes: [], edges: [] });
  const [selectedNode, setSelectedNode] = useState<any | null>(null);
  const [blastRadius, setBlastRadius] = useState<any | null>(null);
  const [attackPaths, setAttackPaths] = useState<any | null>(null);
  const [highlightedPath, setHighlightedPath] = useState<string[]>([]);
  const [blastNodes, setBlastNodes] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    api.listSnapshots().then((snaps) => {
      setSnapshots(snaps);
      if (snaps.length > 0) {
        setSelectedSnapshotId(snaps[0].id);
        loadSnapshot(snaps[0].id);
      }
    });
  }, []);

  async function loadSnapshot(id: string) {
    setIsLoading(true);
    try {
      const snap = await api.getSnapshotFull(id);
      const gj = snap.graphJson || { nodes: [], edges: [] };
      setGraphData(gj);

      // Auto-run attack paths to crown jewels
      const pathsRes = await api.getAttackPaths(id, [], []).catch(() => null);
      setAttackPaths(pathsRes);
    } catch (e) {
      console.error(e);
    } finally {
      setIsLoading(false);
    }
  }

  async function handleCalculateBlastRadius(nodeId: string) {
    if (!selectedSnapshotId) return;
    try {
      const br = await api.getBlastRadius(selectedSnapshotId, [nodeId]);
      setBlastRadius(br);
      const impacted = (br.impacted_nodes || []).map((n: any) => n.node_id);
      setBlastNodes([nodeId, ...impacted]);
    } catch (e: any) {
      alert("Blast radius failed: " + e.message);
    }
  }

  function handleSelectPath(nodes: string[]) {
    setHighlightedPath(nodes);
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "calc(100vh - 120px)", gap: "1rem" }}>
      {/* Control bar */}
      <div
        className="card"
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          padding: "0.6rem 1rem",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.4rem", fontWeight: 700 }}>
            <Network size={18} color="#38bdf8" />
            <span>Topology Explorer</span>
          </div>

          {snapshots.length > 0 && (
            <select
              value={selectedSnapshotId}
              onChange={(e) => {
                setSelectedSnapshotId(e.target.value);
                loadSnapshot(e.target.value);
              }}
              style={{
                background: "#1e293b",
                border: "1px solid #334155",
                color: "#f8fafc",
                padding: "0.3rem 0.6rem",
                borderRadius: "0.375rem",
                fontSize: "0.8rem",
              }}
            >
              {snapshots.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.label} ({s.nodeCount} nodes, {s.edgeCount} edges)
                </option>
              ))}
            </select>
          )}
        </div>

        <div style={{ display: "flex", gap: "0.5rem", fontSize: "0.75rem", color: "#94a3b8" }}>
          <span>Nodes: <b style={{ color: "#f8fafc" }}>{graphData.nodes?.length || 0}</b></span>
          <span>|</span>
          <span>Edges: <b style={{ color: "#f8fafc" }}>{graphData.edges?.length || 0}</b></span>
        </div>
      </div>

      {/* Main Canvas & Overlay */}
      <div style={{ flex: 1, display: "grid", gridTemplateColumns: "1fr 360px", gap: "1rem", position: "relative" }}>
        <div style={{ position: "relative", height: "100%" }}>
          <GraphCanvas
            graphData={graphData}
            onSelectNode={setSelectedNode}
            highlightedPath={highlightedPath}
            blastRadiusNodes={blastNodes}
          />

          <NodeDrawer
            node={selectedNode}
            onClose={() => setSelectedNode(null)}
            onCalculateBlastRadius={handleCalculateBlastRadius}
            onFindPaths={(nodeId) => handleSelectPath([nodeId])}
          />
        </div>

        {/* Right Info Stack */}
        <div style={{ display: "flex", flexDirection: "column", gap: "1rem", overflowY: "auto" }}>
          <BlastRadiusPanel blastRadius={blastRadius} />
          <AttackPathView pathsData={attackPaths} onSelectPath={handleSelectPath} />
        </div>
      </div>
    </div>
  );
}
