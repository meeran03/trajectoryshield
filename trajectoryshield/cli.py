"""Offline entry points; recorded tool calls are data and are never executed."""
from __future__ import annotations
import argparse
from collections import Counter
from dataclasses import asdict
import json
from pathlib import Path
from trajectoryshield.benchmark.gold_standard import get_all_gold_standard
from trajectoryshield.benchmark.trajectory_schema import Trajectory
from trajectoryshield.trajectory_shield.shield import TrajectoryShield


def benchmark():
    cases = get_all_gold_standard()
    shield = TrajectoryShield()
    rows = []
    by_type = {}
    for case in cases:
        verdict = shield.evaluate(case)
        rows.append({'id':case.trajectory_id, 'type':case.label.deception_type,
                     'detected':verdict.detected, 'layer':verdict.blocking_layer})
    for kind in sorted({r['type'] for r in rows}):
        selected = [r for r in rows if r['type']==kind]
        n = sum(r['detected'] for r in selected)
        by_type[kind] = {'total':len(selected),'detected':n,'recall':n/len(selected)}
    count = sum(r['detected'] for r in rows)
    return {'protocol':'Authored synthetic positive-only fixture set; deterministic Layers 1+2; no model calls',
            'total':len(rows),'detected':count,'missed':len(rows)-count,
            'recall':count/len(rows),'false_positive_rate':None,
            'fpr_note':'Undefined: this set contains no honest/negative examples.',
            'by_type':by_type,'cases':rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command',required=True)
    run = sub.add_parser('benchmark',help='Evaluate the included 300 authored fixtures')
    run.add_argument('--output',type=Path)
    inspect = sub.add_parser('inspect',help='Inspect one recorded trajectory without executing it')
    inspect.add_argument('file',type=Path)
    args = parser.parse_args()
    if args.command == 'benchmark':
        result = benchmark()
    else:
        result = asdict(TrajectoryShield().evaluate(Trajectory.load(args.file)))
    text = json.dumps(result,indent=2)+'\n'
    if getattr(args,'output',None):
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(text)
    else:
        print(text,end='')

if __name__ == '__main__':
    main()
