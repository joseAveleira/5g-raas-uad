"""Follow-up window evaluation and separately labelled cross-session service study."""
from pathlib import Path
import argparse, hashlib, json, sys
import numpy as np
import pandas as pd
import joblib
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent))
from src.evaluation import fit_evaluate, metrics, model_pipeline
from src.data import temporal_split

def describe(a,prefix):
    a=np.asarray(a,float); a=a[np.isfinite(a)]
    return {prefix+'_'+k:v for k,v in zip(['mean','std','median','p90'],
      [a.mean(),a.std(),np.median(a),np.quantile(a,.9)] if len(a) else [np.nan]*4)}

def features(d,duration):
    n=len(d); lengths=d.inner_len_declared.to_numpy(float)
    dt=np.diff(d.epoch_us.to_numpy(float))/1e6
    f={'rate_records':n/duration,'rate_declared_bytes':lengths.sum()/duration}
    f.update(describe(lengths,'size'));f.update(describe(dt,'iat'))
    f['size_small_fraction']=float((lengths<=128).mean()) if n else 0.
    f['size_mtu_fraction']=float((lengths>=1400).mean()) if n else 0.
    hist=np.histogram(lengths,bins=[0,64,128,256,512,1024,1400,np.inf])[0]/max(n,1)
    f['size_entropy']=float(-np.sum(hist[hist>0]*np.log2(hist[hist>0])))
    f['iat_burst_fraction']=float((dt<.001).mean()) if len(dt) else np.nan
    for direction,name in [(1,'up'),(-1,'down')]:
        sub=d.loc[d.direction.eq(direction)]
        f[f'{name}_packet_fraction']=len(sub)/max(n,1)
        f[f'{name}_declared_byte_fraction']=sub.inner_len_declared.sum()/max(lengths.sum(),1)
        f[f'{name}_packet_rate']=len(sub)/duration
        f[f'{name}_declared_byte_rate']=sub.inner_len_declared.sum()/duration
        f.update(describe(sub.inner_len_declared,name+'_size'))
    for protocol,name in [(6,'tcp'),(17,'udp'),(1,'icmp')]:
        f['fraction_'+name]=float(d.inner_protocol.eq(protocol).mean()) if n else 0.
    tcp=d.loc[d.inner_protocol.eq(6)]
    f.update(describe(tcp.tcp_window_raw,'tcp_window_raw'))
    f.update(describe(tcp.transport_payload_declared,'tcp_payload_declared'))
    flags=tcp.tcp_flags.to_numpy(int)
    for bit,name in [(1,'fin'),(2,'syn'),(4,'rst'),(16,'ack')]:
        f['fraction_'+name]=float(((flags&bit)!=0).mean()) if len(tcp) else np.nan
    f['flow_count']=d.flow_id.nunique()
    counts=d.groupby('flow_id').inner_len_declared.sum().to_numpy(float)
    shares=counts/max(counts.sum(),1)
    f['flow_byte_entropy']=float(-np.sum(shares[shares>0]*np.log2(shares[shares>0])))
    f['largest_flow_byte_fraction']=float(shares.max()) if len(shares) else 0.
    f['partial_body_fraction']=float(d.inner_missing_bytes.gt(0).mean()) if n else 0.
    return f

def groups(cols,flow=False):
    basic=[c for c in cols if c.startswith(('rate_','size_','iat_'))]
    directional=[c for c in cols if c not in ['partial_body_fraction']]
    if flow:
        directional=[c for c in directional if c not in ['flow_count','flow_byte_entropy','largest_flow_byte_fraction']]
    return {'basic':basic,'directional':directional,'selected_5':directional,
            'capture_context':directional+['partial_body_fraction']}

def label_intervals(path):
    events=[]
    for line in path.read_text(encoding='utf-8-sig').splitlines():
        if not line or line.startswith('#'):continue
        a=[x.strip() for x in line.split('|')]
        events.append({'device':a[1],'action':a[2],'epoch_us':round(float(a[4])*1e6)})
    spans=[]
    for i in range(0,len(events),2):
        a,b=events[i:i+2]; assert a['action']=='START' and b['action']=='STOP' and a['device']==b['device']
        spans.append((a['epoch_us'],b['epoch_us']))
    return spans

def evaluate_case(train,test,cols,group,kind,config,case,task,out,models,seed=42):
    forbidden=['label','epoch','stream','flow_id','source_port','destination_port','teid','sni','inner_src','inner_dst']
    assert all(not any(f in c for f in forbidden) for c in cols)
    model,score,prob,pred=fit_evaluate(train[cols],train.label.to_numpy(),test[cols],test.label.to_numpy(),kind,seed,config,k=5 if group=='selected_5' else None)
    score.update({'case':case,'task':task,'group':group,'model':kind,'seed':seed})
    meta=[c for c in ['row_id','window_id','start','end','block_id','connection_id','capture','label'] if c in test]
    predictions=test[meta].copy();predictions['case']=case;predictions['probability']=prob;predictions['prediction']=pred
    if models:
        joblib.dump({'model':model,'features':cols},out/'models'/f'{case}.joblib')
    selection=[{'case':case,'feature':c} for c in model[:-1].get_feature_names_out()]
    return score,predictions,selection,model

def service_rows(name,inner,decoded,out):
    j=inner.loc[inner.inner_protocol.eq(6)].merge(decoded[['frame.number','tcp.stream','tls.handshake.extensions_server_name']],left_on='frame_number',right_on='frame.number',validate='one_to_one')
    # Every absent stream ID here belongs to an initial fragment with complete
    # transport headers. Carry the observed connection ID within its 5-tuple.
    j=j.sort_values('frame_number')
    j['stream_id']=j.groupby('flow_id')['tcp.stream'].transform(lambda x:x.ffill().bfill())
    j=j.loc[j.stream_id.notna()].copy()
    j['connection_id']=name+':'+j.stream_id.astype(int).astype(str)
    rows={'prefix20_10s':[],'full_flow':[]}; annotations=[]
    for cid,d in j.groupby('connection_id',sort=False):
        snis=sorted(set(str(v).lower().rstrip('.') for v in d['tls.handshake.extensions_server_name'].dropna()))
        is_good=len(snis)==1
        label=int(snis==['dnr-test.com']) if is_good else -1
        annotations.append({'connection_id':cid,'capture':name,'sni':';'.join(snis),'service_label':label,'status':'annotated' if is_good else 'excluded_no_or_ambiguous_sni','packets':len(d),'ue_ip':d.ue_ip.iloc[0]})
        if not is_good:continue
        for view in rows:
            v=d if view=='full_flow' else d.loc[d.epoch_us.le(d.epoch_us.iloc[0]+10_000_000)].head(20)
            duration=max((v.epoch_us.iloc[-1]-v.epoch_us.iloc[0])/1e6,.001)
            record={'connection_id':cid,'capture':name,'label':label,'row_id':len(rows[view]),'packet_count':len(v),'observed_duration':duration}
            record.update(features(v,duration));rows[view].append(record)
    pd.DataFrame(annotations).to_csv(out/f'{name}_service_annotations.csv',index=False)
    result={k:pd.DataFrame(v) for k,v in rows.items()}
    for view,frame in result.items():frame.to_csv(out/f'{name}_service_{view}.csv',index=False)
    return result

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--resources',type=Path,required=True);args=parser.parse_args()
    out=HERE/'results';(out/'models').mkdir(exist_ok=True)
    config=json.loads((HERE.parent/'config.json').read_text())
    inner={n:pd.read_csv(out/f'ransomware-{n}_inner_headers.csv.gz') for n in [2,3]}
    original=pd.read_csv(args.resources/'ransomware_dataset.csv',usecols=['frame_number','frame_time_epoch','frame_len','label'])
    frames=pd.read_csv(out/'ransomware-3_byte_groups.csv.gz')
    assert np.array_equal(original.frame_number,frames.frame_number)
    assert np.array_equal(np.rint(original.frame_time_epoch.to_numpy()*1e6).astype('int64'),frames.epoch_us)
    assert np.array_equal(original.frame_len,frames.wire_len)
    spans=label_intervals(args.resources/'attack_log_wireshark.txt')
    labs=np.zeros(len(original),dtype=int)
    for lo,hi in spans:labs[(frames.epoch_us>=lo)&(frames.epoch_us<=hi)]=1
    assert np.array_equal(labs,original.label)
    t0=int(frames.epoch_us.iloc[0]);cutoff=(spans[0][1]-t0)/1e6
    scores=[];predictions=[];selections=[];controls=[]
    for width in [2,1,5]:
        old=pd.read_csv(HERE.parent/'results/features'/f'candidate_collapsed_all_{width}s.csv')
        for scope in (['complete_only','all_observed_headers'] if width==2 else ['all_observed_headers']):
            rows=[]; data=inner[3]
            if scope=='complete_only':data=data.loc[data.inner_missing_bytes.eq(0)]
            for w in old.itertuples():
                v=data.loc[data.relative_s.ge(w.start)&data.relative_s.lt(w.end)]
                row={k:getattr(w,k) for k in ['window_id','start','end','label','block_id']}
                row.update(features(v,width));rows.append(row)
            windows=pd.DataFrame(rows)
            columns=[c for c in windows if c not in ['window_id','start','end','label','block_id']]
            sets=groups(columns)
            windows.to_csv(out/f'inner_windows_{scope}_{width}s.csv',index=False)
            for direction in (['forward','reverse'] if width==2 else ['forward']):
                tr,te=temporal_split(windows,cutoff,5,direction)
                train,test=windows.iloc[tr],windows.iloc[te]
                for group in (list(sets) if width==2 else ['directional','selected_5']):
                    for kind in ['logistic','forest']:
                        case=f'inner_{scope}_{width}s_{direction}_{group}_{kind}'
                        score,pred,sel,model=evaluate_case(train,test,sets[group],group,kind,config,case,'period_windows',out,models=(width==2 and direction=='forward' and scope=='all_observed_headers'))
                        score.update({'scope':scope,'width':width,'direction':direction})
                        scores.append(score);predictions.append(pred);selections.extend(sel)
                        print(case,round(score['balanced_accuracy'],3),flush=True)
                        if width==2 and direction=='forward' and scope=='all_observed_headers' and group=='directional':
                            y=train.label.to_numpy()
                            for shift in np.unique(np.linspace(1,len(y)-1,20,dtype=int)):
                                m=model_pipeline(kind,42,config);m.fit(train[sets[group]],np.roll(y,shift))
                                result,_=metrics(test.label.to_numpy(),m.predict_proba(test[sets[group]])[:,1])
                                controls.append({'case':case,'shift':int(shift),**result})
    # Independently defined target: observed TLS service identity, not attack state.
    services={}
    for n in [2,3]:
        decoded=pd.read_csv(out/f'ransomware-{n}_byte_collapsed_reassembled.csv',low_memory=False)
        services[n]=service_rows(f'ransomware-{n}',inner[n],decoded,out)
    for view in ['prefix20_10s','full_flow']:
        train,test=services[2][view],services[3][view]
        cols=[c for c in train if c not in ['connection_id','capture','label','row_id','packet_count','observed_duration']]
        sets=groups(cols,flow=True)
        for group in ['basic','directional','selected_5']:
            for kind in ['logistic','forest']:
                case=f'service_oct_to_nov_{view}_{group}_{kind}'
                score,pred,sel,_=evaluate_case(train,test,sets[group],group,kind,config,case,'service_identity',out,models=True)
                score.update({'scope':view,'width':None,'direction':'october_to_november'})
                scores.append(score);predictions.append(pred);selections.extend(sel)
                print(case,round(score['balanced_accuracy'],3),flush=True)
    pd.DataFrame(scores).to_csv(out/'followup_metrics.csv',index=False)
    pd.concat(predictions,ignore_index=True).to_csv(out/'followup_predictions.csv.gz',index=False)
    pd.DataFrame(selections).to_csv(out/'retained_features.csv',index=False)
    pd.DataFrame(controls).to_csv(out/'inner_shift_controls.csv',index=False)
    validation={'original_csv_matches_pcap3_frames_lengths_microsecond_timestamps':True,
      'log_label_disagreements':0,'window_and_service_fits':len(scores),'shift_controls':len(controls),
      'pcap2_attack_periods':'unknown; never assigned from filename or SNI',
      'service_task':'SNI-derived experimental-service identity, not ransomware detection',
      'input_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in args.resources.iterdir() if p.suffix in ['.csv','.pcap','.txt']}}
    (out/'followup_validation.json').write_text(json.dumps(validation,indent=2),encoding='utf-8')
    print(json.dumps(validation,indent=2),flush=True)

if __name__=='__main__':main()
