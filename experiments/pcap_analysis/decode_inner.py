"""Bounds-checked parsing of observed GTP-U/inner headers; never fills missing bytes."""
from pathlib import Path
import collections, hashlib, ipaddress, json, struct
import numpy as np
import pandas as pd
from audit_pcaps import packets

HERE=Path(__file__).resolve().parent
UE_NET=ipaddress.ip_network('12.1.1.0/24')

def u16(b,o): return struct.unpack_from('!H',b,o)[0]
def ipv4(b):
    if len(b)<20 or b[0]>>4!=4: raise ValueError('Missing IPv4 header')
    ihl=(b[0]&15)*4
    if ihl<20 or len(b)<ihl or u16(b,2)<ihl: raise ValueError('Invalid IPv4 header')
    return {'ihl':ihl,'total':u16(b,2),'proto':b[9], 'id':u16(b,4),
      'offset':(u16(b,6)&8191)*8,'mf':bool(u16(b,6)&8192),
      'src':str(ipaddress.ip_address(b[12:16])),'dst':str(ipaddress.ip_address(b[16:20]))}

def decode(data):
    if len(data)<36 or u16(data,14)!=0x0800: return None
    outer=data[16:]; op=ipv4(outer)
    if op['proto']!=17 or op['offset']!=0: return None
    udp=outer[op['ihl']:op['total']]
    if len(udp)<16 or (u16(udp,0)!=2152 and u16(udp,2)!=2152): return None
    gtp=udp[8:]; flags=gtp[0]
    if flags>>5!=1 or not flags&0x10 or gtp[1]!=255: return None
    declared_gtp=8+u16(gtp,2); gtp=gtp[:declared_gtp]
    offset=8; pdu_type=None; qfi=None; next_ext=0
    if flags&7:
        if len(gtp)<12: raise ValueError('Missing optional GTP header')
        offset=12
        if flags&4: next_ext=gtp[11]
    extensions=0
    while next_ext:
        if offset>=len(gtp): raise ValueError('Missing GTP extension length')
        length=gtp[offset]*4
        if length<4 or offset+length>len(gtp): raise ValueError('Incomplete GTP extension')
        if next_ext==0x85:
            pdu_type=gtp[offset+1]>>4; qfi=gtp[offset+2]&63
        next_ext=gtp[offset+length-1]; offset+=length; extensions+=1
        if extensions>32: raise ValueError('Too many GTP extensions')
    inner=gtp[offset:]; ip=ipv4(inner)
    if ip['offset']!=0: raise ValueError('Inner non-initial fragment')
    transport=inner[ip['ihl']:ip['total']]
    sport=dport=0; tcp_flags=0; tcp_window=np.nan; l4_header=0
    if ip['proto']==6:
        if len(transport)<20: raise ValueError('Incomplete TCP base header')
        l4_header=(transport[12]>>4)*4
        if l4_header<20 or len(transport)<l4_header: raise ValueError('Incomplete TCP options')
        sport,dport=u16(transport,0),u16(transport,2)
        tcp_flags=transport[13]; tcp_window=u16(transport,14)
    elif ip['proto']==17:
        if len(transport)<8: raise ValueError('Incomplete UDP header')
        sport,dport=u16(transport,0),u16(transport,2); l4_header=8
    src_ue=ipaddress.ip_address(ip['src']) in UE_NET
    dst_ue=ipaddress.ip_address(ip['dst']) in UE_NET
    direction=1 if src_ue and not dst_ue else -1 if dst_ue and not src_ue else 0
    flow='|'.join(map(str,sorted([(ip['src'],sport),(ip['dst'],dport)])))+'|'+str(ip['proto'])
    record={'outer_src':op['src'],'outer_dst':op['dst'],'outer_id':op['id'],
      'outer_mf':int(op['mf']),'outer_fragment_offset':op['offset'],
      'gtp_teid':struct.unpack_from('!I',gtp,4)[0], 'gtp_header_bytes':offset,
      'gtp_length_declared':declared_gtp-8,'gtp_missing_bytes':max(0,declared_gtp-len(gtp)),
      'pdu_type':pdu_type,'qfi':qfi,'inner_src':ip['src'],'inner_dst':ip['dst'],
      'inner_id':ip['id'],'inner_protocol':ip['proto'],'inner_len_declared':ip['total'],
      'inner_bytes_observed':min(len(inner),ip['total']),
      'inner_missing_bytes':max(0,ip['total']-len(inner)), 'inner_mf':int(ip['mf']),
      'source_port':sport,'destination_port':dport,'tcp_flags':tcp_flags,
      'tcp_window_raw':tcp_window,'transport_payload_declared':max(0,ip['total']-ip['ihl']-l4_header),
      'direction':direction,'ue_ip':ip['src'] if src_ue else ip['dst'] if dst_ue else '',
      'flow_id':hashlib.sha256(flow.encode()).hexdigest()[:24]}
    return record,gtp,inner

def main():
    from scapy.contrib.gtp import GTP_U_Header
    from scapy.layers.inet import IP,TCP,UDP
    out=HERE/'results'; summaries=[]
    for name in ['ransomware-2','ransomware-3']:
        groups=pd.read_csv(out/f'{name}_byte_groups.csv.gz')
        retained=groups.loc[groups.frame_number.eq(groups.byte_group),'frame_number'].to_numpy()
        reference=pd.read_csv(out/f'{name}_byte_collapsed_reassembled.csv',low_memory=False).set_index('frame.number')
        rows=[]; errors=[]; checked=collections.Counter(); matched=0; mismatch=[]
        for frame,us,data,wire in packets(out/f'{name}_byte_collapsed.pcap'):
            try: parsed=decode(data)
            except ValueError as e:
                errors.append({'frame':frame,'error':str(e)}); continue
            if parsed is None: continue
            rec,gtp,inner=parsed
            rec.update({'frame_number':frame,'source_frame':int(retained[frame-1]),'epoch_us':us})
            rec['relative_s']=(us-int(groups.epoch_us.iloc[0]))/1e6
            rows.append(rec)
            # Independent TShark agreement for every complete decoded observation.
            other=reference.loc[frame]
            if pd.notna(other['gtp.teid']):
                # Second IP occurrence is directly inside GTP. ICMP errors may
                # contain a third, quoted IP header, which must not replace it.
                checks={'inner_src':str(other['ip.src']).split('|')[1],
                    'inner_dst':str(other['ip.dst']).split('|')[1],
                    'inner_len_declared':int(str(other['ip.len']).split('|')[1]),
                    'gtp_teid':int(str(other['gtp.teid']),16)}
                if any(rec[k]!=v for k,v in checks.items()): mismatch.append(frame)
                else: matched+=1
            # Independently decode a stratified sample, including incomplete bodies.
            category=(rec['outer_mf'],rec['inner_protocol'],rec['direction'])
            if checked[category]<100:
                independent=GTP_U_Header(gtp)
                assert IP in independent, (name,frame,independent.summary())
                ip=independent[IP]
                assert (ip.src,ip.dst,int(ip.len),int(independent.teid))==(rec['inner_src'],rec['inner_dst'],rec['inner_len_declared'],rec['gtp_teid'])
                if rec['inner_protocol']==6:
                    assert TCP in independent
                    assert (int(ip[TCP].sport),int(ip[TCP].dport),int(ip[TCP].window),int(ip[TCP].flags))==(rec['source_port'],rec['destination_port'],rec['tcp_window_raw'],rec['tcp_flags'])
                elif rec['inner_protocol']==17:
                    assert (int(ip[UDP].sport),int(ip[UDP].dport))==(rec['source_port'],rec['destination_port'])
                checked[category]+=1
        assert not errors, errors[:5]
        assert not mismatch, mismatch[:5]
        d=pd.DataFrame(rows); d.to_csv(out/f'{name}_inner_headers.csv.gz',index=False)
        s={'capture':name,'gtp_inner_observations':len(d),'complete_inner':int(d.inner_missing_bytes.eq(0).sum()),
           'partial_inner_with_complete_transport_headers':int(d.inner_missing_bytes.gt(0).sum()),
           'missing_bytes_counts':d.inner_missing_bytes.value_counts().to_dict(),
           'tshark_complete_agreements':matched,'tshark_mismatches':len(mismatch),
           'scapy_independent_checks':sum(checked.values()),'parse_errors':len(errors),
           'ue_addresses':sorted(d.ue_ip.unique()),'directions':d.direction.value_counts().to_dict(),
           'direction_vs_pdu_type':d.groupby(['direction','pdu_type']).size().to_dict(),
           'inner_protocols':d.inner_protocol.value_counts().to_dict()}
        s['direction_vs_pdu_type']={str(k):int(v) for k,v in s['direction_vs_pdu_type'].items()}
        summaries.append(s); print(json.dumps(s,indent=2),flush=True)
    (out/'inner_header_validation.json').write_text(json.dumps(summaries,indent=2),encoding='utf-8')

if __name__=='__main__': main()
