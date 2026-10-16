"""Independent metric checks, input provenance and service-task confound diagnostics."""
from pathlib import Path
import hashlib,json,sys
import numpy as np,pandas as pd,joblib
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent))
from src.evaluation import metrics,model_pipeline

def main():
    out=HERE/'results';scores=pd.read_csv(out/'followup_metrics.csv');pred=pd.read_csv(out/'followup_predictions.csv.gz')
    for s in scores.itertuples():
        p=pred.loc[pred.case.eq(s.case)]
        actual,labels=metrics(p.label.to_numpy(),p.probability.to_numpy())
        for key,value in actual.items():assert np.isclose(value,getattr(s,key),atol=1e-12),(s.case,key)
        assert np.array_equal(labels,p.prediction)
    service_train=pd.read_csv(out/'ransomware-2_service_prefix20_10s.csv')
    service_test=pd.read_csv(out/'ransomware-3_service_prefix20_10s.csv')
    annotations={n:pd.read_csv(out/f'ransomware-{n}_service_annotations.csv') for n in [2,3]}
    meta=service_test[['connection_id','label']].merge(annotations[3][['connection_id','ue_ip','sni']],on='connection_id',validate='one_to_one')
    c2_ues=set(meta.loc[meta.label.eq(1),'ue_ip'])
    train_domains=set(annotations[2].loc[annotations[2].service_label.eq(0),'sni'])
    subsets={'all_annotated_connections':np.ones(len(meta),bool),
      'only_UEs_with_experimental_service':meta.ue_ip.isin(c2_ues).to_numpy(),
      'positives_and_previously_unseen_other_domains':(meta.label.eq(1)|~meta.sni.isin(train_domains)).to_numpy()}
    subset_results=[];refits=[];nulls=[];configs=json.loads((HERE.parent/'config.json').read_text())
    for group in ['basic','directional','selected_5']:
        case=f'service_oct_to_nov_prefix20_10s_{group}_forest'
        saved=joblib.load(out/'models'/f'{case}.joblib');model=saved['model'];cols=saved['features']
        assert not any(c in cols for c in ['label','sni','ue_ip','connection_id','tcp.stream','source_port','destination_port'])
        # Identical complete feature vectors across captures would be a warning.
        identical=service_train[cols].merge(service_test[cols],on=cols).shape[0]
        prob=model.predict_proba(service_test[cols])[:,1]
        for subset,mask in subsets.items():
            result,_=metrics(service_test.label.to_numpy()[mask],prob[mask]);subset_results.append({'case':case,'subset':subset,**result})
        replica=model_pipeline('forest',42,configs,k=5 if group=='selected_5' else None)
        replica.fit(service_train[cols],service_train.label)
        delta=float(np.abs(prob-replica.predict_proba(service_test[cols])[:,1]).max())
        assert delta<1e-12
        refits.append({'case':case,'max_probability_difference':delta,'identical_feature_vectors_across_captures':identical})
        if group=='directional':
            rng=np.random.default_rng(20261016)
            for i in range(20):
                permutation=rng.permutation(service_train.label.to_numpy())
                null=model_pipeline('forest',42,configs);null.fit(service_train[cols],permutation)
                result,_=metrics(service_test.label.to_numpy(),null.predict_proba(service_test[cols])[:,1]);nulls.append({'iteration':i,**result})
    pd.DataFrame(subset_results).to_csv(out/'service_subset_diagnostics.csv',index=False)
    pd.DataFrame(nulls).to_csv(out/'service_shuffled_label_controls.csv',index=False)
    report={'status':'passed','saved_model_cases_verified':len(scores),'service_refits':refits,
      'service_controls':'20 shuffled training-label diagnostics, not formal cluster-aware p-values',
      'subsets':'Descriptive checks without refitting; same UE means same inner IP within November, not verified physical identity'}
    (out/'independent_validation.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2));print(pd.DataFrame(subset_results).to_string(index=False))
    print('Shuffled-label BA',pd.DataFrame(nulls).balanced_accuracy.agg(['min','median','max']).to_dict())

if __name__=='__main__':main()
