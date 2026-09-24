"""Audit user-supplied JSONL splits without emitting their text or labels."""
import argparse
import hashlib
import json
from pathlib import Path

def audit(files):
    inputs = {}
    hashes = {}
    for name,file in files.items():
        raw = file.read_bytes()
        rows = [json.loads(line) for line in raw.decode().splitlines() if line.strip()]
        inputs[name] = [next(m['content'] for m in r['messages'] if m['role']=='user') for r in rows]
        hashes[name] = hashlib.sha256(raw).hexdigest()
    result = {'method':'Exact equality of serialized user-message model inputs; no normalization or semantic similarity','split_counts':{k:{'rows':len(v),'unique_inputs':len(set(v))} for k,v in inputs.items()},'overlap':{},'source_files_sha256':hashes}
    for a,b in [('train','val'),('train','test'),('val','test')]:
        shared=set(inputs[a])&set(inputs[b])
        result['overlap'][f'{a}_{b}']={'unique_shared_inputs':len(shared),'affected_rows_in_second_split':sum(t in shared for t in inputs[b])}
    return result

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['train','val','test']:parser.add_argument('--'+name,required=True,type=Path)
    args=parser.parse_args()
    print(json.dumps(audit(vars(args)),indent=2))
