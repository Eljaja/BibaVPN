import os, subprocess, tempfile
from pathlib import Path
script=str(Path(__file__).resolve().parents[1] / 'test-changes.sh')
with tempfile.TemporaryDirectory() as d:
 def run(*args, **kw): return subprocess.run(args,cwd=d,check=True,text=True,capture_output=True,**kw)
 run('git','init','-q');run('git','-c','user.name=Test','-c','user.email=test@example.test','commit','--allow-empty','-qm','baseline')
 cases={'apps/bibavpn-desktop/src-tauri/src/lib.rs':'core=false desktop=true mobile=false','bibavpn/src/udp_mux.rs':'core=true desktop=false mobile=false','apps/bibavpn-jni/src/lib.rs':'core=false desktop=false mobile=true','Cargo.lock':'core=true desktop=true mobile=true','.github/agent/work/REVIEW.md':'core=false desktop=false mobile=false'}
 for path,expected in cases.items():
  p=Path(d,path);p.parent.mkdir(parents=True,exist_ok=True);p.write_text('fixture')
  assert run('bash',script,'--plan').stdout.strip()==expected,path
  p.unlink()
 # Execute desktop branch with stub toolchain: runner must retain both failed build and passing desktop log.
 p=Path(d,'apps/bibavpn-desktop/src-tauri/src/lib.rs');p.write_text('fixture')
 bins=Path(d,'stubs');bins.mkdir()
 for tool in ('sudo','npm','cargo'):
  q=bins/tool;q.write_text('#!/bin/sh\necho "$0 $*"\ncase "$*" in "run build"*) exit 7;; esac\n');q.chmod(0o755)
 env=dict(os.environ,PATH=str(bins)+':'+os.environ['PATH'])
 r=subprocess.run(['bash',script],cwd=d,env=env)
 assert r.returncode==1
 log=Path(d,'.github/agent/work/TEST.log').read_text()
 assert 'FAILED: ui-build' in log and 'cargo test -p bibavpn-desktop --locked' in log
 assert 'cargo test -p bibavpn -p biba' not in log
print('PASS: 5 path cases; desktop command selection; failure propagation; accumulated logs')
