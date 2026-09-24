# Reproducibility and release scope

## CPU-only default

Install Python 3.11–3.13, then `pip install -e '.[test]'`. The offline core depends only on Pydantic. Tests use pytest. Run `pytest -q`, `trajectoryshield benchmark`, and `PYTHONPATH=. python scripts/build_demo.py`.

CI tests the supported Python versions, regenerates the public report and browser replay data, and rejects unexpected changes to those artifacts. The browser uses no third-party scripts, trackers, model APIs, or package CDN. It replays precomputed prefix decisions from the Python engine.

The benchmark fixtures contain fictional credentials, domains, and personal records as inert strings. No recorded commands, notifications, file writes, or network requests are executed. Test cases inspect those strings only.

## Optional research modules

The original judge and classifier/training modules are included for inspection and further experimentation. They are not required for the public demonstration.

- `pip install -e '.[judge]'` installs optional model-provider clients. Calls require your own credentials and incur provider costs. Model/provider behavior has not been revalidated for this release.
- `pip install -e '.[training]'` installs optional ML dependencies. Original training was on a CUDA GPU; 4-bit operation additionally requires a compatible bitsandbytes installation. The dependency list is not a verified recreation of the historical GPU environment.
- Weights and original training splits are excluded. A trained adapter is required to use the classifier mode. Base-model inference must not be represented as the trained research classifier.
- Module commands are under `python -m trajectoryshield.trajectory_shield.classifier` and `python -m trajectoryshield.trajectory_shield.train_classifier`. Inspect their help before configuring a new run.

New data preparation groups identical serialized inputs by label, then partitions groups with a seeded generator. It rejects conflicting labels for identical inputs. Group proportions may differ from row proportions; tiny classes can have empty partitions. Further source/template/policy grouping remains future work.

## Excluded from the public artifact

The original repository remains private. This repository starts with a fresh history and contains selected code, authored fixture generators, release documentation, and aggregate experiment outputs. It excludes:

- The paper, PDF, LaTeX source, bibliography, drafts, and thesis build files.
- Environment files, credentials, provider batch identifiers, and private infrastructure scripts.
- Raw third-party patch datasets and historical train/validation/test rows.
- Model weights, training checkpoints, logs, and external tracking configuration.

The [source manifest](source-manifest.json) records hashes of selected original implementation files. [Release notes](release-notes.md) identify changes made while packaging. Historical aggregate output files also record source hashes.
