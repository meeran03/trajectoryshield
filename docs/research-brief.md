# TrajectoryShield: research overview

Muhammad Meeran · Graduate research at Texas Tech University with Professor Akbar Namian

## The question

How can we detect a policy-violating outcome when individual tool actions appear acceptable? A system that checks each action separately can miss a sequence whose cumulative effect violates the policy.

Consider a policy against hardcoded credentials. An agent can write one credential fragment, append another, then combine them. Or it can write a script, execute it, and delete the artifact. The observable sequence matters even when an isolated action looks ordinary.

## The approach

TrajectoryShield evaluates recorded tool calls against a policy using a cascade:

1. **Individual-action predicates.** Inspect selected write operations for local patterns.
2. **Accumulated effects and constraints.** Track file operations, content accumulation, command execution, and external communication; check trajectory and ordering properties.
3. **Optional learned analysis.** Use a model judge or a fine-tuned classifier to assess the serialized trajectory.

The project organizes examples into literal compliance, temporal evasion, and compositional obfuscation. These are operational labels for observable patterns. The system does not establish psychological intent or prove that a model is deceptive.

## What a visitor can reproduce

The public package generates 300 authored synthetic violation fixtures across five domains. Running Layers 1+2 flags 165 and misses 135: 55% recall. Literal-compliance fixtures are particularly difficult for these rules (5/100 detected), while temporal and compositional categories each have 80/100 detections.

This positive-only result cannot establish a false-positive rate. The browser includes separate illustrative honest controls, including a harmless write-and-run sequence that is flagged. The encoded-credential example demonstrates a miss.

These observations expose the method's boundary: accumulating state helps identify some sequences, while broad pattern rules can overflag benign work and miss alternative encodings or indirect effects.

## The historical experiments

The private working corpus contained 2,041 trajectories, combining authored/generated violations and patch-converted honest examples. The release includes aggregate outputs from rule baselines, a model judge, and classifier experiments.

The saved classifier output reports perfect binary classification on 310 test rows. A release audit found exact input overlap with training: 14 distinct shared inputs, affecting 39 test rows. Dataset source also correlates with label. These confounds prevent a clean generalization claim. The public preparation function now groups identical inputs together, but no retraining result is reported.

## Contribution and next evidence needed

This release makes the taxonomy, layered implementation, benchmark generators, and measurement limitations inspectable. It provides a concrete basis for further experiments rather than a claim of comprehensive enforcement.

A stronger next evaluation would use source- and template-grouped splits, independently reviewed labels, representative benign workflows, unseen policies, complete trace instrumentation, and documented model/hardware versions. Any comparison should use the same held-out examples, including both missed violations and false alarms.

The research paper is withheld from this release. This overview is newly written repository documentation, not the manuscript or a claim of publication or peer review.
