# Resultados de la recuperación desde PCAP

Los dos originales son adquisiciones distintas. Solo noviembre dispone de tiempos de ejecución verificados. La tarea de servicio usa etiquetas derivadas del SNI; no equivale a detectar ransomware.

## Inventario y recuperación

| Captura | Paquetes originales | Repeticiones de bytes de red | Representantes | Cabeceras interiores completas recuperadas de cuerpos parciales |
|---|---:|---:|---:|---:|
| ransomware-2.pcap | 123003 | 61501 | 61502 | 15668 |
| ransomware-3.pcap | 107694 | 53832 | 53862 | 11261 |

No hay paquetes truncados por snaplen. Todos los fragmentos IPv4 exteriores observados tienen offset cero; no aparecen colas para completar el reensamblado. El parser recupera cabeceras, no inventa bytes faltantes.

## Todas las comparaciones

| Caso | BA | F1 | Precisión | Recall | TN | FP | FN | TP |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| inner_complete_only_2s_forward_basic_logistic | 0.810 | 0.830 | 0.786 | 0.880 | 17 | 6 | 3 | 22 |
| inner_complete_only_2s_forward_basic_forest | 0.726 | 0.755 | 0.714 | 0.800 | 15 | 8 | 5 | 20 |
| inner_complete_only_2s_forward_directional_logistic | 0.766 | 0.800 | 0.733 | 0.880 | 15 | 8 | 3 | 22 |
| inner_complete_only_2s_forward_directional_forest | 0.724 | 0.764 | 0.700 | 0.840 | 14 | 9 | 4 | 21 |
| inner_complete_only_2s_forward_selected_5_logistic | 0.766 | 0.800 | 0.733 | 0.880 | 15 | 8 | 3 | 22 |
| inner_complete_only_2s_forward_selected_5_forest | 0.744 | 0.786 | 0.710 | 0.880 | 14 | 9 | 3 | 22 |
| inner_complete_only_2s_forward_capture_context_logistic | 0.766 | 0.800 | 0.733 | 0.880 | 15 | 8 | 3 | 22 |
| inner_complete_only_2s_forward_capture_context_forest | 0.724 | 0.764 | 0.700 | 0.840 | 14 | 9 | 4 | 21 |
| inner_complete_only_2s_reverse_basic_logistic | 0.790 | 0.814 | 0.946 | 0.714 | 13 | 2 | 14 | 35 |
| inner_complete_only_2s_reverse_basic_forest | 0.816 | 0.775 | 1.000 | 0.633 | 15 | 0 | 18 | 31 |
| inner_complete_only_2s_reverse_directional_logistic | 0.734 | 0.809 | 0.900 | 0.735 | 11 | 4 | 13 | 36 |
| inner_complete_only_2s_reverse_directional_forest | 0.834 | 0.837 | 0.973 | 0.735 | 14 | 1 | 13 | 36 |
| inner_complete_only_2s_reverse_selected_5_logistic | 0.724 | 0.795 | 0.897 | 0.714 | 11 | 4 | 14 | 35 |
| inner_complete_only_2s_reverse_selected_5_forest | 0.744 | 0.822 | 0.902 | 0.755 | 11 | 4 | 12 | 37 |
| inner_complete_only_2s_reverse_capture_context_logistic | 0.734 | 0.809 | 0.900 | 0.735 | 11 | 4 | 13 | 36 |
| inner_complete_only_2s_reverse_capture_context_forest | 0.834 | 0.837 | 0.973 | 0.735 | 14 | 1 | 13 | 36 |
| inner_all_observed_headers_2s_forward_basic_logistic | 0.766 | 0.800 | 0.733 | 0.880 | 15 | 8 | 3 | 22 |
| inner_all_observed_headers_2s_forward_basic_forest | 0.786 | 0.821 | 0.742 | 0.920 | 15 | 8 | 2 | 23 |
| inner_all_observed_headers_2s_forward_directional_logistic | 0.784 | 0.828 | 0.727 | 0.960 | 14 | 9 | 1 | 24 |
| inner_all_observed_headers_2s_forward_directional_forest | 0.786 | 0.821 | 0.742 | 0.920 | 15 | 8 | 2 | 23 |
| inner_all_observed_headers_2s_forward_selected_5_logistic | 0.831 | 0.846 | 0.815 | 0.880 | 18 | 5 | 3 | 22 |
| inner_all_observed_headers_2s_forward_selected_5_forest | 0.764 | 0.807 | 0.719 | 0.920 | 14 | 9 | 2 | 23 |
| inner_all_observed_headers_2s_forward_capture_context_logistic | 0.784 | 0.828 | 0.727 | 0.960 | 14 | 9 | 1 | 24 |
| inner_all_observed_headers_2s_forward_capture_context_forest | 0.806 | 0.842 | 0.750 | 0.960 | 15 | 8 | 1 | 24 |
| inner_all_observed_headers_2s_reverse_basic_logistic | 0.827 | 0.790 | 1.000 | 0.653 | 15 | 0 | 17 | 32 |
| inner_all_observed_headers_2s_reverse_basic_forest | 0.837 | 0.805 | 1.000 | 0.673 | 15 | 0 | 16 | 33 |
| inner_all_observed_headers_2s_reverse_directional_logistic | 0.865 | 0.876 | 0.975 | 0.796 | 14 | 1 | 10 | 39 |
| inner_all_observed_headers_2s_reverse_directional_forest | 0.847 | 0.819 | 1.000 | 0.694 | 15 | 0 | 15 | 34 |
| inner_all_observed_headers_2s_reverse_selected_5_logistic | 0.814 | 0.810 | 0.971 | 0.694 | 14 | 1 | 15 | 34 |
| inner_all_observed_headers_2s_reverse_selected_5_forest | 0.898 | 0.886 | 1.000 | 0.796 | 15 | 0 | 10 | 39 |
| inner_all_observed_headers_2s_reverse_capture_context_logistic | 0.865 | 0.876 | 0.975 | 0.796 | 14 | 1 | 10 | 39 |
| inner_all_observed_headers_2s_reverse_capture_context_forest | 0.847 | 0.819 | 1.000 | 0.694 | 15 | 0 | 15 | 34 |
| inner_all_observed_headers_1s_forward_directional_logistic | 0.798 | 0.852 | 0.793 | 0.920 | 25 | 12 | 4 | 46 |
| inner_all_observed_headers_1s_forward_directional_forest | 0.784 | 0.844 | 0.780 | 0.920 | 24 | 13 | 4 | 46 |
| inner_all_observed_headers_1s_forward_selected_5_logistic | 0.849 | 0.869 | 0.878 | 0.860 | 31 | 6 | 7 | 43 |
| inner_all_observed_headers_1s_forward_selected_5_forest | 0.771 | 0.836 | 0.767 | 0.920 | 23 | 14 | 4 | 46 |
| inner_all_observed_headers_5s_forward_directional_logistic | 0.682 | 0.720 | 0.562 | 1.000 | 4 | 7 | 0 | 9 |
| inner_all_observed_headers_5s_forward_directional_forest | 0.727 | 0.750 | 0.600 | 1.000 | 5 | 6 | 0 | 9 |
| inner_all_observed_headers_5s_forward_selected_5_logistic | 0.636 | 0.692 | 0.529 | 1.000 | 3 | 8 | 0 | 9 |
| inner_all_observed_headers_5s_forward_selected_5_forest | 0.636 | 0.692 | 0.529 | 1.000 | 3 | 8 | 0 | 9 |
| service_oct_to_nov_prefix20_10s_basic_logistic | 0.977 | 0.972 | 0.972 | 0.972 | 53 | 1 | 1 | 35 |
| service_oct_to_nov_prefix20_10s_basic_forest | 0.986 | 0.986 | 1.000 | 0.972 | 54 | 0 | 1 | 35 |
| service_oct_to_nov_prefix20_10s_directional_logistic | 1.000 | 1.000 | 1.000 | 1.000 | 54 | 0 | 0 | 36 |
| service_oct_to_nov_prefix20_10s_directional_forest | 1.000 | 1.000 | 1.000 | 1.000 | 54 | 0 | 0 | 36 |
| service_oct_to_nov_prefix20_10s_selected_5_logistic | 0.884 | 0.861 | 0.861 | 0.861 | 49 | 5 | 5 | 31 |
| service_oct_to_nov_prefix20_10s_selected_5_forest | 0.991 | 0.986 | 0.973 | 1.000 | 53 | 1 | 0 | 36 |
| service_oct_to_nov_full_flow_basic_logistic | 0.921 | 0.912 | 0.969 | 0.861 | 53 | 1 | 5 | 31 |
| service_oct_to_nov_full_flow_basic_forest | 0.894 | 0.879 | 0.967 | 0.806 | 53 | 1 | 7 | 29 |
| service_oct_to_nov_full_flow_directional_logistic | 0.972 | 0.971 | 1.000 | 0.944 | 54 | 0 | 2 | 34 |
| service_oct_to_nov_full_flow_directional_forest | 1.000 | 1.000 | 1.000 | 1.000 | 54 | 0 | 0 | 36 |
| service_oct_to_nov_full_flow_selected_5_logistic | 0.912 | 0.899 | 0.939 | 0.861 | 52 | 2 | 5 | 31 |
| service_oct_to_nov_full_flow_selected_5_forest | 0.986 | 0.986 | 1.000 | 0.972 | 54 | 0 | 1 | 35 |

## Validación y controles

- Coincidencia del CSV con todos los números de trama, timestamps a microsegundos y longitudes del PCAP de noviembre; cero discrepancias con el registro de ataques.
- Cabeceras coincidentes con TShark en 88.299 observaciones completas y con Scapy en 1.261 observaciones estratificadas, incluidos cuerpos parciales.
- Cinco pruebas unitarias del decodificador pasan. Las métricas de los 52 casos coinciden con las predicciones guardadas.
- Tres entrenamientos de identificación de servicio se reproducen a precisión numérica; ningún vector completo de características coincide entre entrenamiento y test.
- Veinte permutaciones de etiquetas de entrenamiento en la tarea de servicio: BA entre 0,338 y 0,755, mediana 0,539. Son controles descriptivos, no p-valores.
- Los controles temporales por ventanas siguen alcanzando BA hasta 0,790 (RF) y 0,806 (LR). La recuperación no elimina la confusión temporal.
- Las conexiones del servicio experimental tienen tráfico hasta 277,826 s, después del STOP a 273,654 s. Dos de las cinco falsas alarmas del modelo temporal de cinco variables caen en ventanas con ese tráfico. No se cambian las etiquetas ni las métricas.

## Límite de la conclusión

El resultado de 0,991 corresponde a reconocer el servicio experimental frente a otros servicios TLS con SNI observado. El test tiene 90 conexiones, 36 positivas y 54 negativas, en un único día. No es 99,1% de detección general de ransomware. Las conexiones comparten clientes, bibliotecas y servicios; no son experimentos independientes. Faltan actividad legítima comparable contra el mismo backend, otras variantes y más días.
