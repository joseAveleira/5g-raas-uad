"""Reproduce the PCAP follow-up from preserved originals and phase-one window grids."""
from pathlib import Path
import argparse,datetime,hashlib,importlib.metadata,json,os,subprocess,sys
HERE=Path(__file__).resolve().parent

def main():
    p=argparse.ArgumentParser();p.add_argument('--resources',type=Path,default=HERE.parents[2]/'recursos')
    p.add_argument('--manifest-only',action='store_true',help='Record current verified component outputs without rerunning models')
    args=p.parse_args();os.environ.setdefault('LOKY_MAX_CPU_COUNT','2')
    names=['ransomware-2.pcap','ransomware-3.pcap','ransomware_dataset.csv','attack_log_wireshark.txt']
    before={n:hashlib.sha256((args.resources/n).read_bytes()).hexdigest() for n in names}
    if not args.manifest_only:
        steps=[('test_decode.py',[]),('audit_pcaps.py',['--resources',str(args.resources)]),('decode_inner.py',[]),
          ('evaluate_recovery.py',['--resources',str(args.resources)]),('validate_followup.py',[]),('report_followup.py',[])]
        for script,extra in steps:subprocess.run([sys.executable,str(HERE/script),*extra],check=True)
    for n in names:assert hashlib.sha256((args.resources/n).read_bytes()).hexdigest()==before[n]
    manifest={'recorded_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
      'assembled_from_verified_component_runs':args.manifest_only,
      'inputs':before,'python':sys.version,'tshark':subprocess.run(['tshark','--version'],capture_output=True,text=True).stdout.splitlines()[0],
      'packages':{n:importlib.metadata.version(n) for n in ['scapy','numpy','pandas','scipy','scikit-learn','matplotlib','joblib']},
      'source_sha256':{str(f.relative_to(HERE)):hashlib.sha256(f.read_bytes()).hexdigest() for f in [*HERE.glob('*.py'),HERE/'fields.json',HERE/'PROTOCOL.md']},
      'phase_one_configuration_sha256':hashlib.sha256((HERE.parent/'config.json').read_bytes()).hexdigest(),
      'phase_one_model_code_sha256':hashlib.sha256((HERE.parent/'src/evaluation.py').read_bytes()).hexdigest(),
      'validation':json.loads((HERE/'results/independent_validation.json').read_text())['status']}
    (HERE/'results/run_manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print('Manifest recorded; original input checksums preserved')

if __name__=='__main__':main()
