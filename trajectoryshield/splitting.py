"""Group identical model inputs before partitioning; no claim of semantic isolation."""
from __future__ import annotations
import hashlib
import random
from collections import defaultdict


def grouped_split(trajectories, train_ratio=0.7, val_ratio=0.15, seed=42):
    if not 0 < train_ratio < 1 or not 0 <= val_ratio < 1 or train_ratio + val_ratio >= 1:
        raise ValueError('Ratios must leave nonempty train and test proportions')
    groups = defaultdict(list)
    labels = {}
    for item in trajectories:
        key = hashlib.sha256(item.to_serialized_text().encode()).hexdigest()
        label = item.label.deception_type
        if key in labels and labels[key] != label:
            raise ValueError('Identical model inputs have conflicting labels')
        labels[key] = label
        groups[key].append(item)
    by_label = defaultdict(list)
    for key in sorted(groups):
        by_label[labels[key]].append(groups[key])
    rng = random.Random(seed)
    splits = ([], [], [])
    for label in sorted(by_label):
        units = by_label[label]
        rng.shuffle(units)
        a, b = int(len(units)*train_ratio), int(len(units)*(train_ratio+val_ratio))
        for target, part in zip(splits, (units[:a], units[a:b], units[b:])):
            target.extend(item for group in part for item in group)
    return splits
