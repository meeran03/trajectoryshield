"""Guard against accidentally adding manuscripts, environment files, or key material."""
from pathlib import Path
import re
import subprocess
ROOT=Path(__file__).resolve().parents[1]
result=subprocess.run(['git','ls-files'],cwd=ROOT,text=True,capture_output=True)
files=[ROOT/p for p in result.stdout.splitlines()] if result.returncode==0 and result.stdout.strip() else [p for p in ROOT.rglob('*') if p.is_file() and not any(x in p.parts for x in ['.git','.venv','__pycache__','.pytest_cache','build']) and not any(x.endswith('.egg-info') for x in p.parts)]
forbidden_suffixes={'.pdf','.tex','.bib','.aux','.safetensors','.pt','.pem','.key'}
patterns=[re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),re.compile(rb'(?:ghp_|github_pat_)[A-Za-z0-9_]{30,}'),re.compile(rb'sk-(?:proj-|ant-)?[A-Za-z0-9_-]{48,}')]
problems=[]
for file in files:
 rel=file.relative_to(ROOT)
 if file.suffix.lower() in forbidden_suffixes or file.name.startswith('.env') or any(p.lower() in {'thesis','paper','drafts','checkpoints','models'} for p in rel.parts):problems.append(f'Excluded artifact: {rel}')
 if any(pattern.search(file.read_bytes()) for pattern in patterns):problems.append(f'Credential-shaped content: {rel}')
if problems:raise SystemExit('\n'.join(problems))
print(f'Release boundary check passed for {len(files)} files. This is a targeted check, not a complete secret detector.')
