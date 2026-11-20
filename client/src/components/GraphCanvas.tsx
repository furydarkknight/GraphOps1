import { useEffect, useRef } from "react";
import cytoscape, { Core } from "cytoscape";
import dagre from "cytoscape-dagre";

// Register layout extension
cytoscape.use(dagre);

interface GraphCanvasProps {
  graphData: {
    nodes: Array<{ id: string; label: string; type: string; criticality: number; is_crown_jewel?: boolean; [key: string]: any }>;
    edges: Array<{ source: string; target: string; type: string; weight?: number; [key: string]: any }>;
  };
  onSelectNode?: (nodeData: any) => void;
  highlightedPath?: string[];
  blastRadiusNodes?: string[];
}

export function GraphCanvas({ graphData, onSelectNode, highlightedPath, blastRadiusNodes }: GraphCanvasProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    // Convert nodes and edges into Cytoscape elements
    const elements: any[] = [];

    // Color mapper based on criticality and crown jewel
    const getNodeColor = (node: any) => {
      if (node.is_crown_jewel) return "#dc2626"; // Crimson
      if (node.criticality >= 8) return "#ef4444"; // Red
      if (node.criticality >= 6) return "#f97316"; // Orange
      if (node.criticality >= 4) return "#eab308"; // Amber
      if (node.type === "IP" || node.type === "Domain") return "#8b5cf6"; // Purple
      return "#38bdf8"; // Cyan/Blue
    };

    graphData.nodes.forEach((n) => {
      elements.push({
        data: {
          id: n.id,
          label: n.label || n.id,
          type: n.type,
          criticality: n.criticality,
          is_crown_jewel: n.is_crown_jewel,
          color: getNodeColor(n),
          raw: n,
        },
      });
    });

    graphData.edges.forEach((e, idx) => {
      elements.push({
        data: {
          id: `edge-${idx}`,
          source: e.source,
          target: e.target,
          type: e.type,
          raw: e,
        },
      });
    });

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: "node",
          style: {
            "background-color": "data(color)",
            label: "data(label)",
            color: "#f8fafc",
            "font-size": "9px",
            "text-valign": "bottom",
            "text-margin-y": 4,
            width: 22,
            height: 22,
            "border-width": 1.5,
            "border-color": "#1e293b",
          },
        },
        {
          selector: "node[?is_crown_jewel]",
          style: {
            width: 32,
            height: 32,
            "border-width": 3,
            "border-color": "#fbbf24",
            shape: "diamond",
            "font-weight": "bold",
            "font-size": "11px",
          },
        },
        {
          selector: "edge",
          style: {
            width: 1.5,
            "line-color": "#475569",
            "target-arrow-color": "#475569",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            opacity: 0.7,
            "arrow-scale": 0.8,
          },
        },
        {
          selector: "edge[type = 'HAS_ADMIN'], edge[type = 'CAN_REACH']",
          style: {
            width: 2.5,
            "line-color": "#ef4444",
            "target-arrow-color": "#ef4444",
            opacity: 0.9,
          },
        },
        {
          selector: "edge[type = 'LOGGED_IN']",
          style: {
            "line-style": "dashed",
            "line-color": "#f59e0b",
            "target-arrow-color": "#f59e0b",
          },
        },
        {
          selector: ":selected",
          style: {
            "border-width": 4,
            "border-color": "#38bdf8",
          },
        },
      ],
      layout: {
        name: "cose",
        animate: false,
        randomize: false,
        componentSpacing: 60,
        nodeOverlap: 20,
        idealEdgeLength: 50,
      },
    });

    cy.on("tap", "node", (evt) => {
      const nodeData = evt.target.data("raw");
      if (onSelectNode) onSelectNode(nodeData);
    });

    cyRef.current = cy;

    return () => {
      cy.destroy();
    };
  }, [graphData]);

  // Update highlights when path or blast radius changes
  useEffect(() => {
    if (!cyRef.current) return;
    const cy = cyRef.current;

    cy.batch(() => {
      cy.elements().removeClass("highlighted-path blast-impacted");

      if (highlightedPath && highlightedPath.length > 0) {
        highlightedPath.forEach((id) => {
          cy.$id(id).addClass("highlighted-path").css({
            "border-color": "#e11d48",
            "border-width": 4,
          });
        });
      }

      if (blastRadiusNodes && blastRadiusNodes.length > 0) {
        blastRadiusNodes.forEach((id) => {
          cy.$id(id).addClass("blast-impacted").css({
            "background-color": "#f43f5e",
            "border-color": "#fff",
            "border-width": 2,
          });
        });
      }
    });
  }, [highlightedPath, blastRadiusNodes]);

  return (
    <div
      ref={containerRef}
      style={{
        width: "100%",
        height: "100%",
        minHeight: "550px",
        background: "#030712",
        borderRadius: "0.5rem",
        border: "1px solid #1f2937",
        position: "relative",
      }}
    />
  );
}
