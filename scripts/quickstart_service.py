"""Refit the reported compact service-identity case from prepared feature tables."""
from pathlib import Path
import json, sys
import numpy as np
import pandas as pd

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'experiments'))
sys.path.insert(0,str(ROOT/'experiments/pcap_analysis'))
from src.evaluation import model_pipeline, metrics
from evaluate_recovery import groups

def main():
    out=ROOT/'experiments/pcap_analysis/results'
    train=pd.read_csv(out/'ransomware-2_service_prefix20_10s.csv')
    test=pd.read_csv(out/'ransomware-3_service_prefix20_10s.csv')
    metadata={'connection_id','capture','label','row_id','packet_count','observed_duration'}
    cols=groups([c for c in train if c not in metadata],flow=True)['selected_5']
    config=json.loads((ROOT/'experiments/config.json').read_text())
    config['n_jobs']=1
    model=model_pipeline('forest',42,config,k=5)
    model.fit(train[cols],train.label)
    probability=model.predict_proba(test[cols])[:,1]
    scores,prediction=metrics(test.label.to_numpy(),probability)
    case='service_oct_to_nov_prefix20_10s_selected_5_forest'
    saved=pd.read_csv(out/'followup_predictions.csv.gz')
    saved=saved.loc[saved.case.eq(case)].set_index('connection_id').loc[test.connection_id]
    np.testing.assert_allclose(probability,saved.probability,rtol=0,atol=1e-12)
    np.testing.assert_array_equal(prediction,saved.prediction)
    assert (scores['tn'],scores['fp'],scores['fn'],scores['tp'])==(53,1,0,36)
    print(json.dumps({'task':'experimental-service identity, not ransomware detection',
        'train_connections':len(train),'test_connections':len(test),
        'selected_features':model[:-1].get_feature_names_out().tolist(),
        'metrics':scores,'reference_predictions':'matched'},indent=2))

if __name__=='__main__':
    main()
