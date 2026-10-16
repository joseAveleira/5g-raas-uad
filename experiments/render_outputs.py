"""Regenerate figures/report from saved metrics without refitting models."""
import argparse,hashlib,json
from pathlib import Path
from datetime import datetime,timezone
import matplotlib
from src.data import read_capture,candidate_repeats
from src.reporting import create_figures,create_report
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser()
p.add_argument("--input",type=Path,default=HERE.parent.parent/"recursos"/"ransomware_dataset.csv")
p.add_argument("--results",type=Path,default=HERE/"results")
args=p.parse_args()
out=args.results
config=json.loads((out/"config_used.json").read_text())
audit=json.loads((out/"audit/summary.json").read_text())
raw,df,_,_,sha=read_capture(args.input)
assert sha==audit["source_sha256"]
groups,_=candidate_repeats(raw,config["repeat_tolerance_seconds"])
retained=df.loc[df.row_id.eq(groups)]
create_figures(out,df,retained,config,audit)
create_report(out,config,audit)
manifest={"rendered_utc":datetime.now(timezone.utc).isoformat(),"matplotlib":matplotlib.__version__,
          "models_refitted":False,"reporting_source_sha256":hashlib.sha256((HERE/"src/reporting.py").read_bytes()).hexdigest(),
          "change":"Figure legend placement and text size for print; training metrics unchanged."}
(out/"render_manifest.json").write_text(json.dumps(manifest,indent=2),encoding="utf-8")
