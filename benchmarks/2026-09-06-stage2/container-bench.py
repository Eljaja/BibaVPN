# Linux x86_64 lab reproduction; see README.md for prerequisites and scope.
import importlib.util,json,os,secrets,subprocess,tempfile,time
from pathlib import Path
spec=importlib.util.spec_from_file_location('bench',str(Path(__file__).resolve().parents[2]/'scripts/local-throughput-bench.py'));b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
tag='biba-stage2-'+secrets.token_hex(6);owned=[]
size=int(os.environ.get('BENCH_BYTES','268435456'));repeats=int(os.environ.get('BENCH_REPEATS','3'));label=os.environ.get('BENCH_LABEL','baseline')
window=os.environ.get('BENCH_WINDOW');opts=['--mux-window-mib',window] if window else []
with tempfile.TemporaryDirectory(prefix=tag) as tmp:
 lab=Path(tmp)
 try:
  b.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',str(lab/'key.pem'),'-out',str(lab/'cert.pem'),'-subj','/CN=biba-bench.invalid','-addext','subjectAltName=DNS:biba-bench.invalid'])
  (lab/'origin.py').write_text(b.ORIGIN)
  token,psk=secrets.token_hex(24),secrets.token_hex(24)
  b.docker('network','create',tag)
  for suffix in ['origin','server','client']:owned.append(tag+'-'+suffix)
  origin,server,client=owned
  b.docker('run','--rm','-d','--name',origin,'--network',tag,'--network-alias','biba-bench.invalid','-v',f'{lab}:/lab:ro','python:3.12-slim','python','/lab/origin.py',str(size),'0')
  serverbin=os.environ['BENCH_SERVER']
  clientbin=os.environ['BENCH_CLIENT']
  common=['--decoy-max',os.environ.get('BENCH_DECOY','0'),'--max-ws-binary',os.environ.get('BENCH_FRAME','262144'),'--token',token,'--psk',psk,'--proto-domain','bench','--log-level','error']+opts
  b.docker('run','--rm','-d','--name',server,'--network',tag,'-v',f'{lab}:/lab:ro','-v',serverbin+':/server:ro','python:3.12-slim','/server','--listen','0.0.0.0:8443','--cert','/lab/cert.pem','--key','/lab/key.pem',*common)
  b.docker('run','--rm','-d','--name',client,'--network',tag,'-v',f'{lab}:/lab:ro','-v',clientbin+':/client:ro','-v','/usr/bin/curl:/curl:ro','-v','/lib/x86_64-linux-gnu:/hostlibs:ro','python:3.12-slim','/client','--server',server+':8443','--sni','biba-bench.invalid','--pin-cert','/lab/cert.pem','--socks5','127.0.0.1:1080',*common)
  def request(mode,path,limit):
   args=['docker','exec',client,'/hostlibs/ld-linux-x86-64.so.2','--library-path','/hostlibs','/curl','--silent','--show-error','--fail','--max-time',str(limit),'--noproxy','*' if mode=='direct' else '', '--cacert','/lab/cert.pem','-o','/dev/null','-w','%{json}']
   if mode=='mux':args+=['--socks5-hostname','127.0.0.1:1080']
   r=b.run(args+['https://biba-bench.invalid:8080/'+path],timeout=limit+3,check=False)
   try:d=json.loads(r.stdout)
   except ValueError:d={}
   return r,d
  for mode in ['direct','mux']:
   for attempt in range(20):
    r,d=request(mode,'ready',3)
    if not r.returncode:break
    time.sleep(.1)
   b.validate_transfer(r,d,1,mode+' ready')
  print(json.dumps({'event':'setup','label':label,'bytes':size,'repeats':repeats,'window_mib':window or 'default','max_ws_binary':int(os.environ.get('BENCH_FRAME','262144')),'decoy_max':int(os.environ.get('BENCH_DECOY','0')),'topology':'all containers, no published ports'}),flush=True)
  for n in range(repeats):
   for mode in ['direct','mux']:
    r,d=request(mode,'payload',30);b.validate_transfer(r,d,size,mode)
    print(json.dumps({'event':'sample','label':label,'mode':mode,'sample':n+1,'bytes':d['size_download'],'seconds':d['time_total'],'Mbps':size*8/d['time_total']/1e6}),flush=True)
  b.docker('stop','--time','1',server)
  r,d=request('mux','payload',6)
  assert r.returncode and not d.get('size_download',0)
  print(json.dumps({'event':'negative_control','passed':True,'rc':r.returncode,'bytes':d.get('size_download')}),flush=True)
 finally:
  for name in reversed(owned):b.docker('rm','-f',name,check=False)
  b.docker('network','rm',tag,check=False)
