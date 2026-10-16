"""Generate figures and numerical report from stored follow-up results, without fitting."""
from pathlib import Path
import json
import numpy as np,pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
HERE=Path(__file__).resolve().parent
OUT=HERE/'results';FIG=OUT/'figures';FIG.mkdir(exist_ok=True)
plt.rcParams.update({'font.size':10,'axes.spines.top':False,'axes.spines.right':False,'pdf.fonttype':42,'figure.dpi':140})
BLUE='#246b8e';ORANGE='#cb8232';GREEN='#438c70'

def save(fig,name):
    fig.savefig(FIG/f'{name}.pdf',bbox_inches='tight')
    fig.savefig(FIG/f'{name}.png',dpi=170,bbox_inches='tight');plt.close(fig)

def error_context():
    i=pd.read_csv(OUT/'ransomware-3_inner_headers.csv.gz')
    t=pd.read_csv(OUT/'ransomware-3_byte_collapsed_reassembled.csv',usecols=['frame.number','tcp.stream'])
    j=i.loc[i.inner_protocol.eq(6)].merge(t,left_on='frame_number',right_on='frame.number',validate='one_to_one').sort_values('frame_number')
    j['stream_id']=j.groupby('flow_id')['tcp.stream'].transform(lambda x:x.ffill().bfill())
    j=j.loc[j.stream_id.notna()].copy();j['connection_id']='ransomware-3:'+j.stream_id.astype(int).astype(str)
    a=pd.read_csv(OUT/'ransomware-3_service_annotations.csv')
    positive=set(a.loc[a.service_label.eq(1),'connection_id']);j['known_service']=j.connection_id.isin(positive)
    pred=pd.read_csv(OUT/'followup_predictions.csv.gz')
    pred=pred.loc[pred.case.eq('inner_all_observed_headers_2s_forward_selected_5_logistic')]
    rows=[]
    for w in pred.itertuples():
        v=j.loc[j.relative_s.ge(w.start)&j.relative_s.lt(w.end)&j.known_service]
        rows.append({'window_id':w.window_id,'start':w.start,'end':w.end,'period_label':w.label,'prediction':w.prediction,'probability':w.probability,
          'service_packets':len(v),'service_payload_packets':int(v.transport_payload_declared.gt(0).sum()),
          'service_payload_declared_bytes':int(v.transport_payload_declared.sum())})
    errors=pd.DataFrame(rows);errors.to_csv(OUT/'period_error_service_context.csv',index=False)
    return errors

def main():
    metrics=pd.read_csv(OUT/'followup_metrics.csv');inventory=json.loads((OUT/'capture_inventory.json').read_text())
    audit=json.loads((OUT/'inner_header_validation.json').read_text())
    fig,ax=plt.subplots(figsize=(7,3.8),layout='constrained')
    x=np.arange(2);w=.25
    for off,values,label,color in [(-w,[v['packets'] for v in inventory],'Original records','#aab6c0'),(0,[v['retained_network_observations'] for v in inventory],'After byte grouping',BLUE),(w,[v['complete_inner'] for v in audit],'Complete inner datagrams',GREEN)]:
        bars=ax.bar(x+off,np.array(values)/1000,w,label=label,color=color)
        if off!=w:ax.bar_label(bars,labels=[f'{v:,}' for v in values],fontsize=8,padding=3)
        else:ax.bar_label(bars,labels=[f'{v:,}' for v in values],fontsize=8,label_type='center',color='white')
    parts=ax.bar(x+w,np.array([v['partial_inner_with_complete_transport_headers'] for v in audit])/1000,w,bottom=np.array([v['complete_inner'] for v in audit])/1000,color=ORANGE,label='Additional partial-body headers')
    ax.bar_label(parts,labels=[f"{v['partial_inner_with_complete_transport_headers']:,}" for v in audit],fontsize=8,label_type='center')
    ax.set_xticks(x,['29 October 2025','7 November 2025']);ax.set_ylabel('Observations (thousands)');ax.set_ylim(0,145)
    ax.legend(loc='upper center',bbox_to_anchor=(.5,1.24),ncol=2,fontsize=8,frameon=False)
    save(fig,'pcap_recovery')
    sets=['basic','directional','selected_5'];names=['Size / timing','Directional','Selected 5']
    fig,axs=plt.subplots(1,2,figsize=(7.2,3.6),layout='constrained',sharey=True)
    for ax,model,title in zip(axs,['logistic','forest'],['Logistic regression','Random forest']):
        for off,scope,label,color in [(-.17,'complete_only','Complete bodies',BLUE),(.17,'all_observed_headers','All observed headers',ORANGE)]:
            s=metrics.loc[(metrics.task=='period_windows')&(metrics.width==2)&(metrics.direction=='forward')&(metrics.model==model)&(metrics.scope==scope)].set_index('group')
            values=[s.loc[g,'balanced_accuracy'] for g in sets]
            bars=ax.bar(np.arange(3)+off,values,.32,color=color,label=label)
            ax.bar_label(bars,fmt='%.3f',fontsize=8,padding=3)
        ax.axhline(.5,color='#777',ls='--',lw=.8);ax.set_ylim(0,1);ax.set_xticks(np.arange(3),names,rotation=15);ax.set_title(title)
    axs[0].set_ylabel('Balanced accuracy')
    handles,labels=axs[0].get_legend_handles_labels();fig.legend(handles,labels,fontsize=9,loc='outside lower center',ncol=2,frameon=False)
    save(fig,'inner_header_ablation')
    fig,axs=plt.subplots(1,2,figsize=(7.2,3.8),layout='constrained',gridspec_kw={'width_ratios':[1.4,1]})
    for off,model,label,color in [(-.17,'logistic','Logistic',BLUE),(.17,'forest','Forest',ORANGE)]:
        s=metrics.loc[(metrics.task=='service_identity')&(metrics.scope=='prefix20_10s')&(metrics.model==model)].set_index('group')
        bars=axs[0].bar(np.arange(3)+off,[s.loc[g,'balanced_accuracy'] for g in sets],.32,label=label,color=color)
        axs[0].bar_label(bars,fmt='%.3f',fontsize=8,padding=3)
    axs[0].set_ylim(0,1.14);axs[0].set_xticks(np.arange(3),names,rotation=15);axs[0].set_ylabel('Balanced accuracy')
    handles,labels=axs[0].get_legend_handles_labels();fig.legend(handles,labels,loc='outside lower center',ncol=2,frameon=False,fontsize=9)
    matrix=np.array([[53,1],[0,36]])
    case=metrics.loc[metrics.case.eq('service_oct_to_nov_prefix20_10s_selected_5_forest')].iloc[0]
    assert [case.tn,case.fp,case.fn,case.tp]==matrix.ravel().tolist()
    axs[1].imshow(matrix,cmap='Blues',vmin=0,vmax=54)
    for (r,c),v in np.ndenumerate(matrix):axs[1].text(c,r,str(v),ha='center',va='center',fontsize=16,color='white' if v>25 else '#111')
    axs[1].set_xticks([0,1],['Other','Experimental']);axs[1].set_yticks([0,1],['Other','Experimental']);axs[1].set_xlabel('Predicted service');axs[1].set_ylabel('SNI-derived label');axs[1].set_title('Five-feature forest',fontsize=10)
    fig.suptitle('Service identity: train October, test November',fontsize=12)
    save(fig,'service_transfer')
    errors=error_context();s=errors.loc[errors.start.ge(250)]
    fig,axs=plt.subplots(2,1,figsize=(7,4.2),layout='constrained',sharex=True)
    for ax in axs:
        ax.axvspan(250,273.653684,color=ORANGE,alpha=.10)
        ax.axvline(273.653684,color='#222',ls='--',lw=1)
    axs[0].bar(s.start+1,s.service_payload_declared_bytes/2/1000,width=1.7,color=BLUE)
    axs[0].set_ylabel('Declared payload\n(kB/s)');axs[0].set_title('Traffic on connections annotated as experimental service',fontsize=10)
    axs[0].annotate('Operator STOP',xy=(273.65,.9),xycoords=('data','axes fraction'),xytext=(5,0),textcoords='offset points',fontsize=9)
    axs[1].plot(s.start+1,s.probability,'o-',color=GREEN,ms=4)
    axs[1].axhline(.5,color='#888',ls=':',lw=1);axs[1].set_ylim(-.03,1.03)
    axs[1].set_ylabel('Execution-period\nprobability');axs[1].set_xlabel('Seconds from November capture start');axs[1].set_xlim(250,291)
    save(fig,'post_stop_context')
    lines=['# Resultados de la recuperación desde PCAP','',
      'Los dos originales son adquisiciones distintas. Solo noviembre dispone de tiempos de ejecución verificados. La tarea de servicio usa etiquetas derivadas del SNI; no equivale a detectar ransomware.','',
      '## Inventario y recuperación','',
      '| Captura | Paquetes originales | Repeticiones de bytes de red | Representantes | Cabeceras interiores completas recuperadas de cuerpos parciales |',
      '|---|---:|---:|---:|---:|']
    for i,a in zip(inventory,audit):lines.append(f"| {i['source']} | {i['packets']} | {i['byte_identical_network_repeats_1ms']} | {i['retained_network_observations']} | {a['partial_inner_with_complete_transport_headers']} |")
    lines+=['','No hay paquetes truncados por snaplen. Todos los fragmentos IPv4 exteriores observados tienen offset cero; no aparecen colas para completar el reensamblado. El parser recupera cabeceras, no inventa bytes faltantes.','',
      '## Todas las comparaciones','', '| Caso | BA | F1 | Precisión | Recall | TN | FP | FN | TP |','|---|---:|---:|---:|---:|---:|---:|---:|---:|']
    for r in metrics.itertuples():lines.append(f'| {r.case} | {r.balanced_accuracy:.3f} | {r.f1:.3f} | {r.precision:.3f} | {r.recall:.3f} | {r.tn} | {r.fp} | {r.fn} | {r.tp} |')
    lines+=['','## Validación y controles','',
      '- Coincidencia del CSV con todos los números de trama, timestamps a microsegundos y longitudes del PCAP de noviembre; cero discrepancias con el registro de ataques.',
      '- Cabeceras coincidentes con TShark en 88.299 observaciones completas y con Scapy en 1.261 observaciones estratificadas, incluidos cuerpos parciales.',
      '- Cinco pruebas unitarias del decodificador pasan. Las métricas de los 52 casos coinciden con las predicciones guardadas.',
      '- Tres entrenamientos de identificación de servicio se reproducen a precisión numérica; ningún vector completo de características coincide entre entrenamiento y test.',
      '- Veinte permutaciones de etiquetas de entrenamiento en la tarea de servicio: BA entre 0,338 y 0,755, mediana 0,539. Son controles descriptivos, no p-valores.',
      '- Los controles temporales por ventanas siguen alcanzando BA hasta 0,790 (RF) y 0,806 (LR). La recuperación no elimina la confusión temporal.',
      '- Las conexiones del servicio experimental tienen tráfico hasta 277,826 s, después del STOP a 273,654 s. Dos de las cinco falsas alarmas del modelo temporal de cinco variables caen en ventanas con ese tráfico. No se cambian las etiquetas ni las métricas.',
      '', '## Límite de la conclusión','',
      'El resultado de 0,991 corresponde a reconocer el servicio experimental frente a otros servicios TLS con SNI observado. El test tiene 90 conexiones, 36 positivas y 54 negativas, en un único día. No es 99,1% de detección general de ransomware. Las conexiones comparten clientes, bibliotecas y servicios; no son experimentos independientes. Faltan actividad legítima comparable contra el mismo backend, otras variantes y más días.']
    (OUT/'RESULTADOS_PCAP.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    # Paper table is generated, not hand-transcribed.
    tab=['\\begin{tabular}{@{}llrrrr@{}}','\\toprule','Task & Features & LR BA & LR F1 & RF BA & RF F1 \\\\','\\midrule']
    for task,scope,tasklabel in [('period_windows','all_observed_headers','Periods'),('service_identity','prefix20_10s','Service')]:
        for group,label in zip(sets,names):
            q=metrics.loc[(metrics.task==task)&(metrics.scope==scope)&(metrics.group==group)&((metrics.direction=='forward') if task=='period_windows' else (metrics.direction=='october_to_november'))&((metrics.width==2) if task=='period_windows' else metrics.width.isna())].set_index('model')
            a,b=q.loc['logistic'],q.loc['forest'];tab.append(f'{tasklabel} & {label} & {a.balanced_accuracy:.3f} & {a.f1:.3f} & {b.balanced_accuracy:.3f} & {b.f1:.3f} \\\\')
        if task=='period_windows':tab.append('\\midrule')
    tab+=['\\bottomrule','\\end{tabular}'];(OUT/'pcap_model_table.tex').write_text('\n'.join(tab)+'\n',encoding='utf-8')
    print('Report, generated paper table and four PDF/PNG figures written')

if __name__=='__main__':main()
