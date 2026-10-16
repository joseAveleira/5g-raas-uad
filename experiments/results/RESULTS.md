# Resultados de los experimentos del dataset 5G / ransomware

Protocolo: 1.0. Ejecución: 2026-10-16T09:39:08.125725+00:00.
SHA-256 del CSV: a5440e8185b79e90d446a5a710a7f72347767f4b7cd90b697be471534538ae4a.

## Alcance

Estudio exploratorio de una captura de 291,635 segundos, con dos períodos de ejecución de un prototipo. La etiqueta indica un período, no atribuye malicia a cada paquete. La selección se ajusta exclusivamente en entrenamiento. No hay búsqueda de hiperparámetros ni elección del mejor resultado de test. La inspección del esquema y de esta captura orientó el diseño: no es validación externa ciega.

## 1. Calidad y contexto de captura

- 107,694 registros originales; 50,939 candidatos a repetición (47.30%), con 56,755 representantes.
- La clave compara campos exportados salvo índice, tiempos, diferencias temporales, tipo SLL y etiquetas. Solo agrupa coincidencias dentro de 1 ms desde el primer registro del grupo. Se informa también para 10 y 100 microsegundos.
- Sin bytes del PCAP no se certifica igualdad completa ni se descartan todos los paquetes legítimos repetidos. El CSV original no cambia y se compara con la captura sin agrupar.
- 22,522 registros tienen pila sll:ethertype:ip:data, protocolo IP 17, MF activado y trama de [1516] bytes. Su contenido no se decodifica como GTP; no se asignan a túneles sin evidencia adicional.
- Presencia GTP significa presencia del protocolo decodificado, no censo exhaustivo del tráfico de túneles.
- gtp_message y gtp_flags tienen un único valor no nulo. Los 10 TEIDs observados no equivalen a diez dispositivos.

| relationship | records_checked | violations |
| --- | --- | --- |
| frame_cap_len = frame_len | 107694 | 0 |
| ip_len_1 = frame_len - 16 | 107694 | 0 |
| gtp_length = frame_len - 52 | 84994 | 0 |
| udp_length_1 = gtp_length + 16 | 84994 | 0 |

La longitud GTP no introduce información independiente a nivel de paquete junto a longitud de trama y presencia GTP. Sus momentos por ventana condicionados a GTP pueden cambiar la representación respecto a momentos de todas las tramas.

### Visibilidad y agrupación de candidatos

| representation | label | records | decoded_gtp | decoded_gtp_percent | opaque_udp_mf | opaque_udp_mf_percent | other | tcp_all_percent | tcp_among_gtp_percent | quic_among_gtp_percent |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| raw | 0 | 45574 | 40614 | 89.117 | 4866 | 10.677 | 94 | 13.850 | 15.468 | 46.713 |
| raw | 1 | 62120 | 44380 | 71.442 | 17656 | 28.422 | 84 | 21.394 | 29.946 | 59.648 |
| candidate_collapsed | 0 | 24486 | 21973 | 89.737 | 2433 | 9.936 | 80 | 19.448 | 21.536 | 43.512 |
| candidate_collapsed | 1 | 32269 | 23381 | 72.457 | 8828 | 27.358 | 60 | 24.060 | 33.206 | 56.918 |

## 2. Evaluación

Ventanas no solapadas de 2 segundos; sensibilidad de 1 y 5 segundos. Se excluyen ventanas vacías, tramo final incompleto y ventanas que intersectan la incertidumbre entre observaciones de etiquetas distintas. El tiempo sirve para segmentar/separar, nunca para predecir.

Prueba principal: baseline inicial y ejecución 1 para entrenar; baseline posterior, ejecución 2 y baseline final para probar. Corte: 157.316159 s, excluyendo 5 s a cada lado. Entrenamiento: 15 ventanas normales y 49 de ejecución. Prueba: 23 normales y 25 de ejecución.

La dirección inversa es un diagnóstico entre partes de la misma captura; no es prospectiva ni una sesión independiente. Ambas clases están presentes en cada lado.

Modelos fijados: regresión logística balanceada (C=1) y random forest balanceado (200 árboles, profundidad máxima 8, mínimo 2 muestras/hoja). Imputación por mediana, eliminación de constantes y escalado: solo en entrenamiento. Información mutua para seleccionar 5 o 10 variables: solo en entrenamiento. Umbral 0,5 sin optimización en test.

Se excluyen IP, TEID bruto, nombres de endpoints, puertos, IDs de stream, secuencias/checksums, índices y tiempo absoluto. El baseline no incluye campos GTP explícitos, pero longitudes y protocolos pueden codificar indirectamente el contexto; no son intervenciones causales independientes.

## 3. Resultados temporales hacia delante

BA = balanced accuracy. F1, precisión y recall corresponden a ejecución.

| feature_set | model | retained_features | balanced_accuracy | f1 | precision | recall | roc_auc | tn | fp | fn | tp |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| volume | logistic | 14 | 0.746 | 0.778 | 0.724 | 0.840 | 0.765 | 15 | 8 | 4 | 21 |
| volume | forest | 14 | 0.703 | 0.750 | 0.677 | 0.840 | 0.833 | 13 | 10 | 4 | 21 |
| network | logistic | 39 | 0.589 | 0.716 | 0.571 | 0.960 | 0.734 | 5 | 18 | 1 | 24 |
| network | forest | 39 | 0.743 | 0.793 | 0.697 | 0.920 | 0.863 | 13 | 10 | 2 | 23 |
| network_gtp_presence | logistic | 40 | 0.610 | 0.727 | 0.585 | 0.960 | 0.732 | 6 | 17 | 1 | 24 |
| network_gtp_presence | forest | 40 | 0.721 | 0.780 | 0.676 | 0.920 | 0.848 | 12 | 11 | 2 | 23 |
| network_gtp_fields | logistic | 44 | 0.610 | 0.727 | 0.585 | 0.960 | 0.704 | 6 | 17 | 1 | 24 |
| network_gtp_fields | forest | 44 | 0.723 | 0.772 | 0.688 | 0.880 | 0.818 | 13 | 10 | 3 | 22 |
| capture_context | logistic | 46 | 0.610 | 0.727 | 0.585 | 0.960 | 0.710 | 6 | 17 | 1 | 24 |
| capture_context | forest | 46 | 0.723 | 0.772 | 0.688 | 0.880 | 0.822 | 13 | 10 | 3 | 22 |
| gtp_only | logistic | 5 | 0.684 | 0.717 | 0.679 | 0.760 | 0.739 | 14 | 9 | 6 | 19 |
| gtp_only | forest | 5 | 0.748 | 0.769 | 0.741 | 0.800 | 0.746 | 16 | 7 | 5 | 20 |
| selected_5 | logistic | 5 | 0.663 | 0.704 | 0.655 | 0.760 | 0.762 | 13 | 10 | 6 | 19 |
| selected_5 | forest | 5 | 0.724 | 0.764 | 0.700 | 0.840 | 0.789 | 14 | 9 | 4 | 21 |
| selected_10 | logistic | 10 | 0.681 | 0.737 | 0.656 | 0.840 | 0.762 | 12 | 11 | 4 | 21 |
| selected_10 | forest | 10 | 0.724 | 0.764 | 0.700 | 0.840 | 0.776 | 14 | 9 | 4 | 21 |
| dummy | dummy | 14 | 0.500 | 0.685 | 0.521 | 1.000 | 0.500 | 0 | 23 | 0 | 25 |

### Dirección inversa

| feature_set | model | retained_features | balanced_accuracy | f1 | precision | recall | roc_auc | tn | fp | fn | tp |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| volume | logistic | 14 | 0.806 | 0.759 | 1.000 | 0.612 | 0.824 | 15 | 0 | 19 | 30 |
| volume | forest | 14 | 0.803 | 0.795 | 0.971 | 0.673 | 0.845 | 14 | 1 | 16 | 33 |
| network | logistic | 37 | 0.701 | 0.800 | 0.878 | 0.735 | 0.763 | 10 | 5 | 13 | 36 |
| network | forest | 37 | 0.814 | 0.810 | 0.971 | 0.694 | 0.888 | 14 | 1 | 15 | 34 |
| network_gtp_presence | logistic | 38 | 0.701 | 0.800 | 0.878 | 0.735 | 0.763 | 10 | 5 | 13 | 36 |
| network_gtp_presence | forest | 38 | 0.814 | 0.810 | 0.971 | 0.694 | 0.894 | 14 | 1 | 15 | 34 |
| network_gtp_fields | logistic | 42 | 0.701 | 0.800 | 0.878 | 0.735 | 0.765 | 10 | 5 | 13 | 36 |
| network_gtp_fields | forest | 42 | 0.803 | 0.795 | 0.971 | 0.673 | 0.871 | 14 | 1 | 16 | 33 |
| capture_context | logistic | 44 | 0.701 | 0.800 | 0.878 | 0.735 | 0.767 | 10 | 5 | 13 | 36 |
| capture_context | forest | 44 | 0.837 | 0.805 | 1.000 | 0.673 | 0.883 | 15 | 0 | 16 | 33 |
| gtp_only | logistic | 5 | 0.760 | 0.771 | 0.941 | 0.653 | 0.869 | 13 | 2 | 17 | 32 |
| gtp_only | forest | 5 | 0.778 | 0.831 | 0.925 | 0.755 | 0.867 | 12 | 3 | 12 | 37 |
| selected_5 | logistic | 5 | 0.793 | 0.780 | 0.970 | 0.653 | 0.778 | 14 | 1 | 17 | 32 |
| selected_5 | forest | 5 | 0.778 | 0.831 | 0.925 | 0.755 | 0.871 | 12 | 3 | 12 | 37 |
| selected_10 | logistic | 10 | 0.780 | 0.800 | 0.944 | 0.694 | 0.797 | 13 | 2 | 15 | 34 |
| selected_10 | forest | 10 | 0.778 | 0.831 | 0.925 | 0.755 | 0.852 | 12 | 3 | 12 | 37 |
| dummy | dummy | 14 | 0.500 | 0.867 | 0.766 | 1.000 | 0.500 | 0 | 15 | 0 | 49 |

No se promedian las direcciones como sesiones independientes. Se conservan todos los resultados.

## 4. Selección

### 5 variables

- Entrenamiento temprano: gtp_length_std, size_mean, size_median, size_mtu_fraction, tcp_window_size_std.
- Entrenamiento tardío: opaque_fragment_byte_fraction, size_mtu_fraction, size_std, tcp_len_p90, tcp_window_size_std.
- Intersección: 2; Jaccard: 0.250.

### 10 variables

- Entrenamiento temprano: gtp_length_mean, gtp_length_p90, gtp_length_std, opaque_fragment_fraction, size_mean, size_median, size_mtu_fraction, size_std, tcp_len_mean, tcp_window_size_std.
- Entrenamiento tardío: iat_burst_fraction, opaque_fragment_byte_fraction, opaque_fragment_fraction, size_mean, size_mtu_fraction, size_std, tcp_len_p90, tcp_window_size_mean, tcp_window_size_p90, tcp_window_size_std.
- Intersección: 5; Jaccard: 0.333.

La importancia por permutación se calcula en test después de entrenar para interpretar. No decide la selección ni reajusta el modelo. Su dispersión no es un intervalo de confianza de generalización.

## 5. Sensibilidad a ventana, repeticiones y tráfico GTP decodificado

| representation | scope | width | feature_set | model | balanced_accuracy | f1 |
| --- | --- | --- | --- | --- | --- | --- |
| candidate_collapsed | all | 2 | network | logistic | 0.589 | 0.716 |
| candidate_collapsed | all | 2 | network | forest | 0.743 | 0.793 |
| candidate_collapsed | all | 2 | capture_context | logistic | 0.610 | 0.727 |
| candidate_collapsed | all | 2 | capture_context | forest | 0.723 | 0.772 |
| candidate_collapsed | all | 2 | selected_5 | logistic | 0.663 | 0.704 |
| candidate_collapsed | all | 2 | selected_5 | forest | 0.724 | 0.764 |
| candidate_collapsed | all | 1 | network | logistic | 0.629 | 0.774 |
| candidate_collapsed | all | 1 | network | forest | 0.673 | 0.768 |
| candidate_collapsed | all | 1 | capture_context | logistic | 0.609 | 0.754 |
| candidate_collapsed | all | 1 | capture_context | forest | 0.683 | 0.779 |
| candidate_collapsed | all | 1 | selected_5 | logistic | 0.748 | 0.796 |
| candidate_collapsed | all | 1 | selected_5 | forest | 0.818 | 0.854 |
| candidate_collapsed | all | 5 | network | logistic | 0.500 | 0.621 |
| candidate_collapsed | all | 5 | network | forest | 0.535 | 0.615 |
| candidate_collapsed | all | 5 | capture_context | logistic | 0.500 | 0.621 |
| candidate_collapsed | all | 5 | capture_context | forest | 0.535 | 0.615 |
| candidate_collapsed | all | 5 | selected_5 | logistic | 0.626 | 0.667 |
| candidate_collapsed | all | 5 | selected_5 | forest | 0.707 | 0.700 |
| candidate_collapsed | decoded_gtp | 2 | network | logistic | 0.665 | 0.754 |
| candidate_collapsed | decoded_gtp | 2 | network | forest | 0.713 | 0.772 |
| candidate_collapsed | decoded_gtp | 2 | selected_5 | logistic | 0.675 | 0.717 |
| candidate_collapsed | decoded_gtp | 2 | selected_5 | forest | 0.713 | 0.772 |
| candidate_collapsed | decoded_gtp | 1 | network | logistic | 0.646 | 0.780 |
| candidate_collapsed | decoded_gtp | 1 | network | forest | 0.664 | 0.783 |
| candidate_collapsed | decoded_gtp | 1 | selected_5 | logistic | 0.691 | 0.778 |
| candidate_collapsed | decoded_gtp | 1 | selected_5 | forest | 0.673 | 0.775 |
| candidate_collapsed | decoded_gtp | 5 | network | logistic | 0.500 | 0.643 |
| candidate_collapsed | decoded_gtp | 5 | network | forest | 0.544 | 0.640 |
| candidate_collapsed | decoded_gtp | 5 | selected_5 | logistic | 0.694 | 0.727 |
| candidate_collapsed | decoded_gtp | 5 | selected_5 | forest | 0.694 | 0.727 |
| raw | all | 2 | network | logistic | 0.587 | 0.725 |
| raw | all | 2 | network | forest | 0.719 | 0.787 |
| raw | all | 2 | capture_context | logistic | 0.589 | 0.716 |
| raw | all | 2 | capture_context | forest | 0.723 | 0.772 |
| raw | all | 2 | selected_5 | logistic | 0.704 | 0.741 |
| raw | all | 2 | selected_5 | forest | 0.746 | 0.778 |

Restringir a GTP decodificado excluye UDP opaco y cambia la población; no demuestra que descartar fragmentos sea una solución general.

## 6. Particiones por paquete y control de tiempo

| split | model | shared_candidate_groups | test_rows_with_candidate_in_training_fraction | balanced_accuracy | f1 | roc_auc |
| --- | --- | --- | --- | --- | --- | --- |
| random_packet | forest_packet_features | 21201 | 0.656 | 0.716 | 0.788 | 0.781 |
| random_packet | time_only_invalid_detector_control | 21201 | 0.656 | 1.000 | 1.000 | 1.000 |
| random_candidate_group | forest_packet_features | 0 | 0.000 | 0.705 | 0.780 | 0.771 |
| forward_time | forest_packet_features | 0 | 0.000 | 0.593 | 0.653 | 0.457 |
| forward_time | time_only_invalid_detector_control | 0 | 0.000 | 0.500 | 0.616 | 0.500 |
| forward_time_candidate_collapsed | forest_packet_features | 0 | 0.000 | 0.525 | 0.605 | 0.352 |

La partición aleatoria es un diagnóstico. Agrupar candidatos evita compartirlos entre lados, pero sigue mezclando períodos vecinos. Las diferencias frente al test temporal pueden reflejar dependencia, cambio de tráfico y poblaciones de prueba distintas; no se atribuyen solo a duplicados.

El control solo de tiempo es deliberadamente inválido como detector: la construcción temporal de la etiqueta puede aprenderse sin información de red. Sus puntuaciones no son rendimiento útil.

## 7. Controles

### Otras semillas fijadas

| feature_set | seed | balanced_accuracy | f1 |
| --- | --- | --- | --- |
| network | 17 | 0.721 | 0.780 |
| network | 73 | 0.719 | 0.787 |
| capture_context | 17 | 0.681 | 0.737 |
| capture_context | 73 | 0.723 | 0.772 |
| selected_5 | 17 | 0.724 | 0.764 |
| selected_5 | 73 | 0.703 | 0.750 |

### Desplazamientos circulares de etiquetas de entrenamiento

| model | count | min | median | max |
| --- | --- | --- | --- | --- |
| forest | 20 | 0.262 | 0.593 | 0.748 |
| logistic | 20 | 0.263 | 0.567 | 0.768 |

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
