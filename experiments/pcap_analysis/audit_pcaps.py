"""Read-only PCAP provenance, byte-repeat audit and reproducible TShark export."""
from pathlib import Path
import argparse, collections, hashlib, json, struct, subprocess
import pandas as pd

HERE = Path(__file__).resolve().parent

def packets(path):
    with path.open('rb') as f:
        h=f.read(24)
        formats={b'\xd4\xc3\xb2\xa1':('<',1_000_000),b'\xa1\xb2\xc3\xd4':('>',1_000_000)}
        endian, scale=formats[h[:4]]
        assert struct.unpack(endian+'I',h[20:24])[0]==113, 'Expected Linux SLL v1'
        number=0
        while head:=f.read(16):
            assert len(head)==16
            sec,sub,cap,wire=struct.unpack(endian+'IIII',head)
            data=f.read(cap)
            assert len(data)==cap
            number+=1
            yield number, sec*scale+sub, data, wire

def write_pcap(path, selected):
    with path.open('wb') as f:
        f.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,262144,113))
        for number,us,data,wire in selected:
            sec,micro=divmod(us,1_000_000)
            f.write(struct.pack('<IIII',sec,micro,len(data),wire)); f.write(data)

def audit(path,out):
    source_hash=hashlib.sha256(path.read_bytes()).hexdigest()
    last={}; last_full={}; rows=[]; selected=[]; first=None; whole_repeats=0
    type_pairs=collections.Counter()
    for number,us,data,wire in packets(path):
        assert len(data)>=16
        first=us if first is None else first
        pkttype=struct.unpack('!H',data[:2])[0]
        # Equality uses literal bytes, not a feature hash or label-dependent key.
        key=data[16:]
        old=last.get(key)
        if old is None or us-old[1]>1000:
            group=number; last[key]=(number,us,pkttype)
            selected.append((number,us,data,wire))
        else:
            group=old[0]; type_pairs[f'{old[2]}->{pkttype}']+=1
        old_full=last_full.get(data)
        if old_full is None or us-old_full[1]>1000: last_full[data]=(number,us)
        else: whole_repeats+=1
        rows.append((number,us,(us-first)/1e6,len(data),wire,pkttype,group))
    frame=pd.DataFrame(rows,columns=['frame_number','epoch_us','relative_s','captured_len','wire_len','sll_pkttype','byte_group'])
    frame.to_csv(out/f'{path.stem}_byte_groups.csv.gz',index=False)
    write_pcap(out/f'{path.stem}_byte_collapsed.pcap',selected)
    report={'source':path.name,'sha256':source_hash,'bytes':path.stat().st_size,
      'packets':len(frame),'duration_s':float(frame.relative_s.iloc[-1]),
      'first_epoch_us':int(frame.epoch_us.iloc[0]),'last_epoch_us':int(frame.epoch_us.iloc[-1]),
      'byte_identical_network_repeats_1ms':len(frame)-len(selected),'retained_network_observations':len(selected),
      'full_frame_repeats_1ms':whole_repeats,'sll_type_pairs':dict(type_pairs),
      'truncated_frames':int(frame.captured_len.lt(frame.wire_len).sum()),
      'policy':'Literal bytes after 16-byte SLL header; 1 ms from group anchor; original retained; not proof of capture topology.'}
    assert hashlib.sha256(path.read_bytes()).hexdigest()==source_hash
    return report

def export(path,output,fields,reassemble=True):
    command=['tshark','-n','-2','-r',str(path),'-o',f'ip.defragment:{str(reassemble).upper()}',
      '-o','tcp.desegment_tcp_streams:TRUE','-T','fields','-E','header=y','-E','separator=,','-E','quote=d','-E','occurrence=a','-E','aggregator=|']
    for field in fields: command.extend(['-e',field])
    with output.open('wb') as f:
        result=subprocess.run(command,stdout=f,stderr=subprocess.PIPE,check=True)
    return {'input':str(path),'output':str(output),'command':command,'stderr':result.stderr.decode('utf-8','replace')}

def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--resources',type=Path,required=True)
    args=parser.parse_args(); out=HERE/'results'; out.mkdir(exist_ok=True)
    fields=json.loads((HERE/'fields.json').read_text())
    reports=[]; commands=[]
    for name in ['ransomware-2.pcap','ransomware-3.pcap']:
        path=args.resources/name
        print('Auditing',name,flush=True)
        reports.append(audit(path,out))
        for source in [path,out/f'{path.stem}_byte_collapsed.pcap']:
            print('Exporting',source.name,flush=True)
            commands.append(export(source,out/f'{source.stem}_reassembled.csv',fields))
    pd.DataFrame(reports).to_csv(out/'capture_inventory.csv',index=False)
    (out/'capture_inventory.json').write_text(json.dumps(reports,indent=2),encoding='utf-8')
    (out/'extraction_commands.json').write_text(json.dumps(commands,indent=2),encoding='utf-8')
    print(json.dumps(reports,indent=2),flush=True)

if __name__=='__main__': main()
