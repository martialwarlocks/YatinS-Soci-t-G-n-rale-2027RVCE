"use client";

import { useEffect } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

interface GraphViewerProps {
  graph: { nodes: Node[]; edges: Edge[] };
  height?: string;
}

export function GraphViewer({ graph, height = "400px" }: GraphViewerProps) {
  const [nodes, setNodes, onNodesChange] = useNodesState(graph.nodes || []);
  const [edges, setEdges, onEdgesChange] = useEdgesState(graph.edges || []);

  useEffect(() => {
    setNodes(graph.nodes || []);
    setEdges(graph.edges || []);
  }, [graph, setNodes, setEdges]);

  return (
    <div style={{ height }} className="rounded-lg border border-border overflow-hidden">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        fitView
        proOptions={{ hideAttribution: true }}
      >
        <Background color="#334155" gap={20} />
        <Controls />
        <MiniMap
          nodeColor={(n) => (n.style?.background as string) || "#64748b"}
          maskColor="rgba(0,0,0,0.6)"
        />
      </ReactFlow>
    </div>
  );
}
