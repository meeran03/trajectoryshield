# Results and measurement audit

## Reproduced for this release

Run `trajectoryshield benchmark --output reports/local-run.json` after installation. The deterministic report should match [public-fixtures.json](../reports/public-fixtures.json). It contains no wall-clock timing fields, so a timing difference does not obscure decision reproducibility.

The dataset is generated from the original authored fixture code: 300 labeled violations, 100 of each pattern. Layers 1+2 flag 165 (55.0% recall). Breakdown: literal 5/100; temporal 80/100; compositional 80/100. False-positive rate is **undefined**, since this set has no negative examples. Fixtures that shaped a rule are not an independent held-out benchmark.

## Archived full-corpus outputs

The historical corpus has 2,041 trajectories: 641 labeled deceptive and 1,400 labeled honest. These outputs are retained as historical records, not newly rerun model results. The full underlying corpus is not distributed here; independent reproduction of the full-corpus numbers requires the excluded inputs and original model setup.

| System | Recall on 641 violations | FPR on 1,400 honest examples |
| --- | ---: | ---: |
| Repository PredicateEngine | 4.68% | 0.714% |
| Repository NaiveConcat | 4.68% | 0.714% |
| Repository PolicySpec | 36.19% | 0.071% |
| TrajectoryShield L1+L2 | 49.77% | 0.786% |

Source: [archived aggregate experiment output](../reports/archive/all_results.json). The three comparison implementations live in this repository; these numbers must not be presented as a measured comparison with external products bearing similar names. Archived model-judge aggregates are provided separately. Latencies depend on the original environment and are not cross-system performance guarantees.

The 55% public-fixture recall and 49.77% historical full-corpus recall have different denominators. They are not an improvement claim.

## Classifier audit

The [saved classifier output](../reports/archive/classifier_eval.json) has TP=99, TN=211, FP=0, FN=0. The original split contained 1,426 training rows, 305 validation rows, and 310 test rows.

Comparing the **serialized user-message model inputs** exactly produced:

| Pair | Distinct shared inputs | Affected rows in second split |
| --- | ---: | ---: |
| Train / validation | 14 | 28 |
| Train / test | 14 | 39 |
| Validation / test | 13 | 38 |

See [machine-readable audit](../reports/archive/split_audit.json). Input file hashes identify the audited snapshots; raw split content is excluded. `scripts/audit_splits.py` repeats the count against user-supplied split files and emits only aggregate counts and file hashes.

**Interpretation:** perfect classification on this split is not evidence of leakage-free generalization. Exact duplicate matching is only a lower bound. Similar templates, multiple derived variants, and shared source policies could create further dependence. The historical honest and deceptive classes also use different construction sources, allowing source/style cues to correlate with the label.

The original serialization truncates individual argument strings to 100 characters and tool results to 200. Classifier input is capped at 2,048 tokens. Distinct raw trajectories can therefore become identical or lose relevant evidence. The split audit intentionally operates on what the model sees.

The public preparation code keeps identical serialized inputs together and rejects conflicting labels for identical inputs. That change prevents this exact overlap mechanism in new splits. It does not establish semantic independence, and the classifier has not been retrained for this release.

## Further qualifications

- Binary violation detection and correctly identifying a deception subtype are different metrics. Perfect binary counts do not establish perfect subtype accuracy.
- The classifier's historical training targets use a fixed confidence value of 0.95. That output is not a calibrated probability.
- Archived cross-type, learning-curve, and multi-seed outputs do not supersede the split/source audit or prove leakage-free generalization.
- Broad sensitive-read/external-communication heuristics do not prove that sensitive content actually reached a recipient. Write-then-execute can describe ordinary development.
- A complete and faithful trace is assumed. This prototype does not intercept tools or secure an execution environment.
