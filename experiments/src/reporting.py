import json
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

LABELS = {"volume":"Volume / timing", "network":"Network",
          "network_gtp_presence":"Network + GTP presence",
          "network_gtp_fields":"Network + GTP fields",
          "capture_context":"Network + GTP + fragments",
          "gtp_only":"GTP only", "selected_5":"Selected 5", "selected_10":"Selected 10",
          "dummy":"Majority reference"}
ORDER = list(LABELS)
COLOR = {"logistic":"#26678a", "forest":"#c98235"}


def main_rows(m, width=2, direction="forward"):
    return m.loc[m.representation.eq("candidate_collapsed") & m.scope.eq("all") &
                 m.width.eq(width) & m.direction.eq(direction) &
                 m.experiment.eq("main_or_sensitivity")].copy()


def savefig(fig, out, name):
    fig.savefig(out / "figures" / (name + ".pdf"), bbox_inches="tight")
    fig.savefig(out / "figures" / (name + ".png"), dpi=180, bbox_inches="tight")
    plt.close(fig)


def create_figures(out, raw, retained, config, audit):
    plt.rcParams.update({"font.family":"DejaVu Sans", "font.size":12,
                         "pdf.fonttype":42, "axes.spines.top":False,
                         "axes.spines.right":False})
    m = pd.read_csv(out/"metrics/window_metrics.csv")
    visibility = pd.read_csv(out/"audit/protocol_visibility.csv")
    primary = config["primary_window_seconds"]
    fig, axes = plt.subplots(1, 2, figsize=(8,4.2), constrained_layout=True)
    x = np.arange(4)
    labels = ["Raw\nbaseline","Raw\nexecution","Collapsed\nbaseline","Collapsed\nexecution"]
    bottom = np.zeros(4)
    for col, lab, color in [("decoded_gtp","Decoded GTP","#26678a"),
                             ("opaque_udp_mf","Opaque UDP / MF","#c98235"),
                             ("other","Other","#9aa5af")]:
        values = visibility[col].to_numpy() / visibility.records.to_numpy() * 100
        axes[0].bar(x,values,bottom=bottom,label=lab,color=color)
        bottom += values
    axes[0].set(xticks=x,xticklabels=labels,ylabel="Captured records (%)",ylim=(0,108),
                title="(a) Protocol visibility")
    axes[0].legend(loc="upper center",bbox_to_anchor=(.5,-.20),ncol=2,fontsize=9,frameon=False)
    g = retained.loc[retained.has_gtp.eq(1)]
    points = g.iloc[np.linspace(0,len(g)-1,min(2000,len(g))).astype(int)]
    axes[1].scatter(points.frame_len,points.gtp_length,s=7,alpha=.25,color="#26678a")
    axes[1].set(xlabel="Frame length (bytes)",ylabel="GTP length (bytes)",
                title="(b) Exact length redundancy")
    axes[1].text(.05,.86,"GTP length = frame length - 52\n84,994 / 84,994 raw records",transform=axes[1].transAxes,fontsize=10)
    savefig(fig,out,"capture_audit")

    splits=pd.read_csv(out/"features/split_manifest.csv")
    s=splits.loc[splits.representation.eq("candidate_collapsed") & splits.scope.eq("all") &
                 splits.width.eq(primary) & splits.direction.eq("forward")]
    fig,ax=plt.subplots(figsize=(9,2.8),constrained_layout=True)
    for _,r in s.iterrows():
        color="#26678a" if r.label==0 else "#c98235"
        ax.broken_barh([(r.start,r.end-r.start)],(.05,.7),facecolors=color,
                       alpha=.2 if r.assignment=="embargo" else .9)
    cutoff=audit["temporal_cutoff_s"];gap=config["embargo_seconds_each_side"]
    ax.axvspan(cutoff-gap,cutoff+gap,color="#777777",alpha=.18,label="Embargo")
    ax.axvline(cutoff,color="#444444",ls="--",lw=1)
    ax.text((cutoff-gap)/2,.9,"TRAIN: baseline + execution 1",ha="center",fontsize=9)
    ax.text((cutoff+gap+292)/2,.9,"TEST: later baseline + execution 2",ha="center",fontsize=9)
    ax.scatter([],[],color="#26678a",marker="s",label="Baseline")
    ax.scatter([],[],color="#c98235",marker="s",label="Execution")
    ax.set(xlim=(0,292),ylim=(0,1.1),yticks=[],xlabel="Time since capture start (s)",
           title=f"Non-overlapping {primary}-second windows; boundary/empty/partial bins omitted")
    ax.legend(ncol=3,loc="lower center",bbox_to_anchor=(.5,-.55),frameon=False)
    savefig(fig,out,"temporal_protocol")

    fig,axes=plt.subplots(1,2,figsize=(8,5.4),sharey=True,constrained_layout=True)
    for ax,direction in zip(axes,["forward","reverse"]):
        sub=main_rows(m,primary,direction)
        for offset,kind in [(-.17,"logistic"),(.17,"forest")]:
            ordered=[float(sub.loc[sub.feature_set.eq(name)&sub.model.eq(kind),"balanced_accuracy"].iloc[0])
                     for name in ORDER[:-1]]
            ax.barh(np.arange(8)+offset,ordered,height=.32,color=COLOR[kind],label=kind.title())
        ax.axvline(.5,color="#777777",ls="--",lw=1)
        ax.set(yticks=np.arange(8),yticklabels=[LABELS[x] for x in ORDER[:-1]],
               xlim=(0,1.03),xlabel="Balanced accuracy",
               title="Forward test" if direction=="forward" else "Reverse diagnostic")
        ax.grid(axis="x",alpha=.15);ax.set_axisbelow(True)
    axes[0].invert_yaxis();axes[1].legend(loc="lower right",frameon=False)
    savefig(fig,out,"feature_ablation")

    fig,axes=plt.subplots(1,2,figsize=(9,3.5),constrained_layout=True)
    for ax,kind in zip(axes,["logistic","forest"]):
        for name,color in [("network","#26678a"),("capture_context","#c98235"),("selected_5","#58946c")]:
            sub=m.loc[m.representation.eq("candidate_collapsed") & m.scope.eq("all") &
                      m.direction.eq("forward") & m.model.eq(kind) & m.feature_set.eq(name) &
                      m.experiment.eq("main_or_sensitivity")].sort_values("width")
            ax.plot(sub.width,sub.balanced_accuracy,"o-",color=color,label=LABELS[name])
        ax.axhline(.5,color="#777777",ls="--",lw=1)
        ax.set(xlabel="Window duration (s)",ylabel="Balanced accuracy",ylim=(0,1.02),
               xticks=[1,2,5],title=kind.title())
        ax.grid(alpha=.15)
    axes[1].legend(fontsize=8,loc="lower right",frameon=False)
    savefig(fig,out,"window_sensitivity")

    pi=pd.read_csv(out/"metrics/heldout_permutation_importance.csv").head(12).iloc[::-1]
    fig,ax=plt.subplots(figsize=(8,4.3),constrained_layout=True)
    ax.barh(pi.feature.str.replace("_"," "),pi.mean_BA_decrease,xerr=pi.permutation_sd,
            color="#26678a",alpha=.85,capsize=2)
    ax.axvline(0,color="#777777",lw=1)
    ax.set(xlabel="Test balanced-accuracy decrease after permutation",
           title="Held-out importance: full context random forest\nPost-hoc interpretation; not used for selection")
    savefig(fig,out,"heldout_importance")

    timeline=pd.read_csv(out/"audit/tunnel_timeline.csv")
    pivot=timeline.pivot(index="tunnel_alias",columns="time_bin",values="records").fillna(0)
    pivot=pivot.reindex(columns=np.arange(146),fill_value=0)
    fig,ax=plt.subplots(figsize=(9,4),constrained_layout=True)
    im=ax.imshow(np.log1p(pivot.to_numpy()),aspect="auto",origin="lower",extent=(0,292,-.5,len(pivot)-.5),
                 cmap="Blues",interpolation="nearest")
    boundaries=audit["label_boundary_uncertainty"]
    for lo,hi in [(boundaries[0][1],boundaries[1][0]),(boundaries[2][1],boundaries[3][0])]:
        ax.axvline(lo,color="#c98235",lw=.8,ls="--");ax.axvline(hi,color="#c98235",lw=.8,ls="--")
    ax.set(yticks=np.arange(len(pivot)),yticklabels=pivot.index,xlabel="Time since capture start (s)",
           ylabel="Local TEID alias",title="Decoded GTP observations by tunnel (candidate repeats collapsed)")
    fig.colorbar(im,ax=ax,label="log(1 + records per 2 s)")
    savefig(fig,out,"tunnel_activity")

    preds=pd.read_csv(out/"predictions/window_predictions.csv.gz")
    fig,ax=plt.subplots(figsize=(9,3.5),constrained_layout=True)
    for name,color in [("capture_context","#26678a"),("selected_5","#c98235")]:
        case=f"candidate_collapsed_all_{primary}s_forward_{name}_forest_{config['seed']}"
        sub=preds.loc[preds.case.eq(case)]
        ax.plot((sub.start+sub.end)/2,sub.probability,"o-",ms=3,color=color,label=LABELS[name])
    for _,row in sub.loc[sub.label.eq(1)].sort_values("start").iterrows():
        ax.axvspan(row.start,row.end,color="#e7ccaa",alpha=.25,lw=0)
    ax.axhline(.5,color="#777777",ls="--",lw=1)
    ax.set(xlabel="Time since capture start (s)",ylabel="Execution-class probability",
           ylim=(-.03,1.03),title="Forward held-out windows; shading marks execution-labelled segments")
    ax.legend(frameon=False,fontsize=8)
    savefig(fig,out,"heldout_timeline")


def markdown_table(df):
    def fmt(v):
        if isinstance(v,(float,np.floating)): return f"{v:.3f}" if np.isfinite(v) else ""
        return str(v).replace("|","/")
    rows=["| "+" | ".join(map(str,df.columns))+" |","| "+" | ".join(["---"]*len(df.columns))+" |"]
    rows.extend("| "+" | ".join(fmt(x) for x in row)+" |" for row in df.itertuples(index=False,name=None))
    return "\n".join(rows)


def create_report(out, config, audit):
    m=pd.read_csv(out/"metrics/window_metrics.csv")
    primary=config["primary_window_seconds"]
    main=main_rows(m,primary)
    reverse=main_rows(m,primary,"reverse")
    packet=pd.read_csv(out/"metrics/packet_split_diagnostics.csv")
    shift=pd.read_csv(out/"metrics/circular_shift_controls.csv")
    visibility=pd.read_csv(out/"audit/protocol_visibility.csv")
    redundancy=pd.read_csv(out/"audit/redundancy.csv")
    stability=json.loads((out/"metrics/selection_stability.json").read_text())
    manifest=json.loads((out/"run_manifest.json").read_text())
    columns=["feature_set","model","retained_features","balanced_accuracy","f1","precision","recall","roc_auc","tn","fp","fn","tp"]
    sensitivity=m.loc[m.direction.eq("forward") & m.feature_set.isin(["network","capture_context","selected_5"]) &
                      m.experiment.eq("main_or_sensitivity"),
                      ["representation","scope","width","feature_set","model","balanced_accuracy","f1"]]
    source=main.iloc[0]
    report=f"""# Resultados de los experimentos del dataset 5G / ransomware

Protocolo: {config['protocol_version']}. Ejecución: {manifest['completed_utc']}.
SHA-256 del CSV: {audit['source_sha256']}.

## Alcance

Estudio exploratorio de una captura de 291,635 segundos, con dos períodos de ejecución de un prototipo. La etiqueta indica un período, no atribuye malicia a cada paquete. La selección se ajusta exclusivamente en entrenamiento. No hay búsqueda de hiperparámetros ni elección del mejor resultado de test. La inspección del esquema y de esta captura orientó el diseño: no es validación externa ciega.

## 1. Calidad y contexto de captura

- {audit['raw_records']:,} registros originales; {audit['candidate_repeated_records']:,} candidatos a repetición ({audit['candidate_repeated_percent']:.2f}%), con {audit['retained_records']:,} representantes.
- La clave compara campos exportados salvo índice, tiempos, diferencias temporales, tipo SLL y etiquetas. Solo agrupa coincidencias dentro de 1 ms desde el primer registro del grupo. Se informa también para 10 y 100 microsegundos.
- Sin bytes del PCAP no se certifica igualdad completa ni se descartan todos los paquetes legítimos repetidos. El CSV original no cambia y se compara con la captura sin agrupar.
- {audit['opaque_udp_mf_records']:,} registros tienen pila sll:ethertype:ip:data, protocolo IP 17, MF activado y trama de {audit['opaque_udp_mf_frame_lengths']} bytes. Su contenido no se decodifica como GTP; no se asignan a túneles sin evidencia adicional.
- Presencia GTP significa presencia del protocolo decodificado, no censo exhaustivo del tráfico de túneles.
- gtp_message y gtp_flags tienen un único valor no nulo. Los {audit['teids_observed']} TEIDs observados no equivalen a diez dispositivos.

{markdown_table(redundancy)}

La longitud GTP no introduce información independiente a nivel de paquete junto a longitud de trama y presencia GTP. Sus momentos por ventana condicionados a GTP pueden cambiar la representación respecto a momentos de todas las tramas.

### Visibilidad y agrupación de candidatos

{markdown_table(visibility)}

## 2. Evaluación

Ventanas no solapadas de {primary} segundos; sensibilidad de 1 y 5 segundos. Se excluyen ventanas vacías, tramo final incompleto y ventanas que intersectan la incertidumbre entre observaciones de etiquetas distintas. El tiempo sirve para segmentar/separar, nunca para predecir.

Prueba principal: baseline inicial y ejecución 1 para entrenar; baseline posterior, ejecución 2 y baseline final para probar. Corte: {audit['temporal_cutoff_s']:.6f} s, excluyendo {config['embargo_seconds_each_side']} s a cada lado. Entrenamiento: {int(source.train_normal)} ventanas normales y {int(source.train_execution)} de ejecución. Prueba: {int(source.test_normal)} normales y {int(source.test_execution)} de ejecución.

La dirección inversa es un diagnóstico entre partes de la misma captura; no es prospectiva ni una sesión independiente. Ambas clases están presentes en cada lado.

Modelos fijados: regresión logística balanceada (C=1) y random forest balanceado ({config['forest_trees']} árboles, profundidad máxima {config['forest_max_depth']}, mínimo {config['forest_min_leaf']} muestras/hoja). Imputación por mediana, eliminación de constantes y escalado: solo en entrenamiento. Información mutua para seleccionar 5 o 10 variables: solo en entrenamiento. Umbral 0,5 sin optimización en test.

Se excluyen IP, TEID bruto, nombres de endpoints, puertos, IDs de stream, secuencias/checksums, índices y tiempo absoluto. El baseline no incluye campos GTP explícitos, pero longitudes y protocolos pueden codificar indirectamente el contexto; no son intervenciones causales independientes.

## 3. Resultados temporales hacia delante

BA = balanced accuracy. F1, precisión y recall corresponden a ejecución.

{markdown_table(main[columns])}

### Dirección inversa

{markdown_table(reverse[columns])}

No se promedian las direcciones como sesiones independientes. Se conservan todos los resultados.

## 4. Selección

"""
    for item in stability:
        report+=f"""### {item['k']} variables

- Entrenamiento temprano: {', '.join(item['forward_features'])}.
- Entrenamiento tardío: {', '.join(item['reverse_features'])}.
- Intersección: {item['intersection']}; Jaccard: {item['jaccard']:.3f}.

"""
    report+=f"""La importancia por permutación se calcula en test después de entrenar para interpretar. No decide la selección ni reajusta el modelo. Su dispersión no es un intervalo de confianza de generalización.

## 5. Sensibilidad a ventana, repeticiones y tráfico GTP decodificado

{markdown_table(sensitivity)}

Restringir a GTP decodificado excluye UDP opaco y cambia la población; no demuestra que descartar fragmentos sea una solución general.

## 6. Particiones por paquete y control de tiempo

{markdown_table(packet[['split','model','shared_candidate_groups','test_rows_with_candidate_in_training_fraction','balanced_accuracy','f1','roc_auc']])}

La partición aleatoria es un diagnóstico. Agrupar candidatos evita compartirlos entre lados, pero sigue mezclando períodos vecinos. Las diferencias frente al test temporal pueden reflejar dependencia, cambio de tráfico y poblaciones de prueba distintas; no se atribuyen solo a duplicados.

El control solo de tiempo es deliberadamente inválido como detector: la construcción temporal de la etiqueta puede aprenderse sin información de red. Sus puntuaciones no son rendimiento útil.

## 7. Controles

### Otras semillas fijadas

{markdown_table(m.loc[m.experiment.eq('seed_sensitivity'), ['feature_set','seed','balanced_accuracy','f1']])}

### Desplazamientos circulares de etiquetas de entrenamiento

{markdown_table(shift.groupby('model').balanced_accuracy.agg(['count','min','median','max']).reset_index())}

Se conservan clases y estructura serial mediante desplazamiento circular, cambiando solo etiquetas de entrenamiento. Es control descriptivo, no test de significación ni p-valor. Con pocas transiciones, otros alineamientos pueden obtener puntuaciones altas.

## 8. Interpretación y límites

Se aporta caracterización reproducible de redundancia, repetición, visibilidad, actividad por túnel, representaciones y sensibilidad. Los clasificadores distinguen regímenes de esta captura en el grado indicado en las tablas; no prueban detección universal de ransomware.

Fragmentos, duplicados reales y asociación túnel/dispositivo requieren PCAP/log. La generalización exige nuevas sesiones/días/dispositivos y una prueba externa reservada. Las 107.694 filas no son 107.694 ejecuciones independientes.

## Archivos

- config_used.json y run_manifest.json: configuración, versiones, hashes y ajustes ejecutados.
- audit/: esquema, repeticiones, redundancia, visibilidad y túneles.
- features/: matrices, exclusiones, grupos y asignaciones temporales.
- metrics/: todas las métricas, selección, controles e importancia.
- predictions/: probabilidades y predicciones por muestra.
- models/: modelos ajustados; cargar solo archivos propios/confiables.
- figures/: PDF vectorial y PNG; tables/: tabla LaTeX generada.

Referencias metodológicas: [Arp et al., USENIX Security 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/arp), [scikit-learn: evitar fuga de información](https://scikit-learn.org/stable/common_pitfalls.html).
"""
    (out/"RESULTS.md").write_text(report,encoding="utf-8")
    lines=[r"\begin{tabularx}{\textwidth}{@{}L r r r r r@{}}",r"\toprule",
           "Feature set & $k$ & LR BA & LR F1 & RF BA & RF F1 "+chr(92)*2,r"\midrule"]
    for name in ORDER[:-1]:
        lr=main.loc[main.feature_set.eq(name)&main.model.eq("logistic")].iloc[0]
        rf=main.loc[main.feature_set.eq(name)&main.model.eq("forest")].iloc[0]
        lines.append(f"{LABELS[name]} & {int(lr.retained_features)} & "
                     f"{lr.balanced_accuracy:.3f} & {lr.f1:.3f} & {rf.balanced_accuracy:.3f} & {rf.f1:.3f} "+chr(92)*2)
    lines.extend([r"\bottomrule",r"\end{tabularx}"])
    (out/"tables"/"forward_ablation.tex").write_text("\n".join(lines)+"\n",encoding="utf-8")
