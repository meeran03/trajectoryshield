# Public release 0.1.0

This release packages existing research rather than creating a replacement demonstration.

- Moved selected original `src` modules into the `trajectoryshield` namespace; updated their internal imports.
- Added a minimal installable package, offline CLI, benchmark report, and interactive prefix-replay interface.
- Preserved the original rule predicates, effect heuristics, policy checks, and authored fixture logic.
- Added explicit errors for unknown policies, malformed step order, and requested but unconfigured Layer 3 modes.
- Required a trained adapter for the classifier, preventing unadapted base-model inference from being mislabeled as the trained classifier.
- Grouped identical serialized inputs before future classifier data splitting. Archived results remain unchanged; no corrected training result is implied.
- Removed unqualified latency/cost promises from module introductions.
- Added aggregate historical outputs, a split overlap audit, and reproducibility/limitations documentation.
- Excluded the manuscript and its supporting files from the working release and public history.

The original full-corpus and model experiments were not rerun for this release. The included 300-fixture deterministic run and browser replay are regenerated and checked in CI.
