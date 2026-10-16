"""Validate saved predictions, splits, source identity and deterministic refits."""
import argparse
import hashlib
import json
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.metrics import balanced_accuracy_score, f1_score, confusion_matrix
from src.data import read_capture, candidate_repeats, temporal_split, forbidden_feature
from src.evaluation import fit_evaluate

HERE=Path(__file__).resolve().parent
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument("--input",type=Path,default=HERE.parent.parent/"recursos"/"ransomware_dataset.csv")
parser.add_argument("--results",type=Path,default=HERE/"results")
args=parser.parse_args()
out=args.results
config=json.loads((out/"config_used.json").read_text())
manifest=json.loads((out/"run_manifest.json").read_text())
assert hashlib.sha256(args.input.read_bytes()).hexdigest()==manifest["input_sha256"]
raw,df,boundaries,cutoff,_=read_capture(args.input)
groups,_=candidate_repeats(raw,config["repeat_tolerance_seconds"])
df["candidate_group"]=groups
keep=df.row_id.eq(df.candidate_group)
scores=pd.read_csv(out/"metrics/window_metrics.csv")
predictions=pd.read_csv(out/"predictions/window_predictions.csv.gz")
checked=0
for _,s in scores.loc[scores.experiment.eq("main_or_sensitivity")].iterrows():
    p=predictions.loc[predictions.case.eq(s.case)]
    assert len(p)==s.test_normal+s.test_execution
    assert np.isclose(balanced_accuracy_score(p.label,p.prediction),s.balanced_accuracy)
    assert np.isclose(f1_score(p.label,p.prediction,zero_division=0),s.f1)
    np.testing.assert_array_equal(confusion_matrix(p.label,p.prediction,labels=[0,1]).ravel(),
                                  s[["tn","fp","fn","tp"]].to_numpy(int))
    checked+=1
coverage=[]
for file in sorted((out/"features").glob("*s.csv")):
    name=file.stem
    width=int(name.rsplit("_",1)[-1][:-1])
    scope="decoded_gtp" if "decoded_gtp" in name else "all"
    data=df.loc[keep] if name.startswith("candidate_collapsed") else df
    if scope=="decoded_gtp":data=data.loc[data.has_gtp.eq(1)]
    w=pd.read_csv(file)
    for _,row in w.iterrows():
        samples=data.loc[data.t.ge(row.start)&data.t.lt(row.end)]
        assert len(samples)==row.n_rows
        assert samples.label.nunique()==1 and samples.label.iloc[0]==row.label
        assert not any(row.start<=hi and row.end>lo for lo,hi in boundaries)
    present_bins=set(np.floor(data.t/width).astype(int))
    complete_bins=set(range(int(df.t.max()//width)))
    coverage.append({"matrix":name,"included_windows":len(w),
                     "complete_grid_bins":len(complete_bins),
                     "empty_complete_bins":len(complete_bins-present_bins)})
    cols=json.loads((out/"features"/f"{name}_groups.json").read_text())
    assert not any(forbidden_feature(c) for v in cols.values() for c in v)
    tr,te=temporal_split(w,cutoff,config["embargo_seconds_each_side"])
    train_groups=set(data.loc[data.t.lt(cutoff-config["embargo_seconds_each_side"]),"candidate_group"])
    test_groups=set(data.loc[data.t.ge(cutoff+config["embargo_seconds_each_side"]),"candidate_group"])
    assert not train_groups & test_groups
pd.DataFrame(coverage).to_csv(out/"audit/window_coverage_validation.csv",index=False)
refits=[]
primary=config["primary_window_seconds"]
stem=f"candidate_collapsed_all_{primary}s"
w=pd.read_csv(out/"features"/f"{stem}.csv")
cols=json.loads((out/"features"/f"{stem}_groups.json").read_text())
tr,te=temporal_split(w,cutoff,config["embargo_seconds_each_side"])
for name,k in [("capture_context",None),("selected_5",5)]:
    model,result,prob,pred=fit_evaluate(w.iloc[tr][cols[name]],w.label.iloc[tr],
                                      w.iloc[te][cols[name]],w.label.iloc[te],
                                      "forest",config["seed"],config,k)
    case=f"{stem}_forward_{name}_forest_{config['seed']}"
    previous=predictions.loc[predictions.case.eq(case)].sort_values("window_id")
    np.testing.assert_allclose(prob,previous.probability,rtol=0,atol=1e-12)
    np.testing.assert_array_equal(pred,previous.prediction)
    refits.append({"case":case,"max_probability_difference":float(np.max(np.abs(prob-previous.probability)))})
validation={"status":"passed","saved_window_cases_recomputed":checked,
            "window_matrices_checked":len(coverage),"source_unchanged":True,
            "candidate_groups_shared_across_temporal_split":0,
            "deterministic_refits":refits,
            "test_suite":"python -m unittest discover -s experiments/tests -v"}
(out/"validation.json").write_text(json.dumps(validation,indent=2),encoding="utf-8")
print(json.dumps(validation,indent=2))
