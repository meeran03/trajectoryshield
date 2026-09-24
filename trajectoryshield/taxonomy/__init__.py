"""
Deception Taxonomy Module

Formal definitions of deceptive policy compliance types
for tool-using LLM agents.
"""

from trajectoryshield.taxonomy.deception_types import (
    DeceptionType,
    LiteralCompliance,
    TemporalEvasion,
    CompositionalObfuscation,
    DeceptionInstance,
    classify_deception,
)
from trajectoryshield.taxonomy.ltl_properties import (
    LTLProperty,
    StepProperty,
    TrajectoryProperty,
    TemporalProperty,
    PolicySpecification,
)
