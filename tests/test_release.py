import json
from pathlib import Path
import pytest
from trajectoryshield.benchmark.gold_standard import get_all_gold_standard
from trajectoryshield.splitting import grouped_split
from trajectoryshield.trajectory_shield.shield import TrajectoryShield
from trajectoryshield.cli import benchmark
ROOT=Path(__file__).resolve().parents[1]

def test_report_matches_public_engine():
    assert benchmark()==json.loads((ROOT/'reports/public-fixtures.json').read_text())
    assert benchmark()['false_positive_rate'] is None

def test_identical_model_inputs_stay_together():
    cases=get_all_gold_standard()
    cases += [t.model_copy(update={'trajectory_id':t.trajectory_id+'-copy'}) for t in cases[:20]]
    splits=grouped_split(cases)
    assert sum(map(len,splits))==len(cases)
    inputs=[{t.to_serialized_text() for t in part} for part in splits]
    assert not inputs[0]&inputs[1]
    assert not inputs[0]&inputs[2]
    assert not inputs[1]&inputs[2]
    assert [[t.trajectory_id for t in p] for p in splits]==[[t.trajectory_id for t in p] for p in grouped_split(cases)]

def test_conflicting_input_labels_rejected():
    t=get_all_gold_standard()[0]
    other=t.model_copy(update={'label':t.label.model_copy(update={'deception_type':'honest'})})
    with pytest.raises(ValueError,match='conflicting'):grouped_split([t,other])

def test_unknown_policy_and_unconfigured_layer_are_errors():
    with pytest.raises(ValueError,match='Unsupported policy'):TrajectoryShield(policy_id='missing').evaluate(get_all_gold_standard()[0])
    with pytest.raises(ValueError,match='explicit judge'):TrajectoryShield(enable_layer3=True)
    with pytest.raises(ValueError,match='adapter'):TrajectoryShield(enable_layer3=True,layer3_mode='classifier')
    with pytest.raises(ValueError,match='Unknown Layer'):TrajectoryShield(enable_layer3=True,layer3_mode='missing')

def test_duplicate_step_numbers_rejected():
    t=get_all_gold_standard()[0]
    calls=[c.model_copy(update={'step':0}) for c in t.tool_calls]
    with pytest.raises(ValueError,match='unique and increasing'):TrajectoryShield().evaluate(t.model_copy(update={'tool_calls':calls}))

def test_demo_includes_a_miss_and_a_false_alarm():
    cases=json.loads((ROOT/'site/data.js').read_text().removeprefix('window.TRACE_DATA = ').removesuffix(';\n'))['cases']
    assert any(c['expected_violation'] and not c['prefixes'][-1]['detected'] for c in cases)
    assert any(not c['expected_violation'] and c['prefixes'][-1]['detected'] for c in cases)
