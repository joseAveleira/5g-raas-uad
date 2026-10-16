"""Verify compressed inputs and recompute every recorded second-phase metric."""
from pathlib import Path
import gzip, hashlib, json, sys
import numpy as np
import pandas as pd

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'experiments'))
from src.evaluation import metrics

def main():
    manifest=json.loads((ROOT/'recursos/manifest.json').read_text())
    for entry in manifest:
        path=ROOT/entry['stored_as']
        with path.open('rb') as f: stored=hashlib.file_digest(f,'sha256').hexdigest()
        assert stored==entry['stored_sha256'],path.name
        opener=gzip.open if path.suffix=='.gz' else open
        with opener(path,'rb') as f: original=hashlib.file_digest(f,'sha256').hexdigest()
        assert original==entry['original_sha256'],path.name
    out=ROOT/'experiments/pcap_analysis/results'
    scores=pd.read_csv(out/'followup_metrics.csv')
    predictions=pd.read_csv(out/'followup_predictions.csv.gz')
    for row in scores.itertuples():
        pred=predictions.loc[predictions.case.eq(row.case)]
        actual,labels=metrics(pred.label.to_numpy(),pred.probability.to_numpy())
        for key,value in actual.items():
            assert np.isclose(value,getattr(row,key),atol=1e-12),(row.case,key)
        np.testing.assert_array_equal(labels,pred.prediction)
    print(json.dumps({'source_files_verified':len(manifest),'recorded_cases_verified':len(scores),'status':'passed'},indent=2))

if __name__=='__main__':
    main()
