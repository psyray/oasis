"""Integration checks: LangGraph node ids stay aligned with dashboard phase rows and the compiled graph."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oasis.agent.graph_labels import GRAPH_PIPELINE_NODE_AND_PHASE_ID
from oasis.enums import PhaseRowStatus, ProgressPhaseRowId
from oasis.helpers.graph_progress import graph_pipeline_phases


class TestLanggraphPipelineAlignment(unittest.TestCase):
    def test_graph_progress_phase_row_ids_match_graph_labels(self):
        phases = graph_pipeline_phases(
            n_files=2,
            nv=3,
            discover_status=PhaseRowStatus.COMPLETE.value,
            discover_completed=3,
            scan_status=PhaseRowStatus.COMPLETE.value,
            scan_completed=1,
            scan_total=1,
            expand_status=PhaseRowStatus.COMPLETE.value,
            expand_completed=1,
            expand_total=1,
            deep_status=PhaseRowStatus.COMPLETE.value,
            deep_completed=1,
            deep_total=1,
            verify_status=PhaseRowStatus.COMPLETE.value,
            verify_completed=1,
            verify_total=1,
        )
        self.assertEqual(phases[0]["id"], ProgressPhaseRowId.EMBEDDINGS.value)
        expected = [pair[1] for pair in GRAPH_PIPELINE_NODE_AND_PHASE_ID]
        self.assertEqual([p["id"] for p in phases[1:]], expected)

    def test_compiled_graph_contains_pipeline_nodes(self):
        try:
            from oasis.agent.graph import build_oasis_analysis_graph
        except ImportError as exc:
            self.skipTest(f"agent graph unavailable: {exc}")

        compiled = build_oasis_analysis_graph()
        expected_nodes = {pair[0] for pair in GRAPH_PIPELINE_NODE_AND_PHASE_ID}
        expected_nodes.add("report")
        expected_nodes.add("poc")

        # Compiled LangGraph inherits Pregel with a ``nodes`` mapping (strings → specs).
        nodes_map = getattr(compiled, "nodes", None)
        if not isinstance(nodes_map, dict):
            self.skipTest("compiled graph has no nodes dict; phase row id test still guards dashboard wiring")

        missing = expected_nodes - set(nodes_map.keys())
        self.assertFalse(
            missing,
            f"compiled graph missing nodes {sorted(missing)}; update graph.py or GRAPH_PIPELINE_NODE_AND_PHASE_ID",
        )


if __name__ == "__main__":
    unittest.main()
