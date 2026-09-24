"""
TrajectoryShield: Multi-layer deception detection for tool-using agents.

Architecture:
    Layer 1: Step-level predicates (reuse existing PredicateEngine)
    Layer 2: FSM conformance + effect accumulation
    Layer 3: Trajectory-level reasoning (LLM judge or learned classifier)
"""
