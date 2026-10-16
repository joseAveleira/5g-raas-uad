# Análisis desde los PCAP originales

Esta segunda fase conserva la primera y añade una comprobación de bytes, recuperación de cabeceras interiores, evaluación temporal y una tarea distinta de identificación de servicio entre días. Empezar por `CONCLUSIONES_PCAP.md` y `results/RESULTADOS_PCAP.md`.

## Reproducir

Desde la raíz de `computer_communications`, con Python 3.13 y TShark 4.6.4 en PATH:

    python -m pip install -r experiments/pcap_analysis/requirements-lock.txt
    python experiments/pcap_analysis/run_pcap_study.py --resources recursos

Instalar las dependencias del archivo requirements-lock.txt. Esta carpeta conserva el estudio validado; la guía principal del repositorio describe la versión pública. La ejecución usa los cuatro originales de recursos y las cuadrículas de ventanas de la primera fase, que se distribuyen en experiments/results/features. Los originales se leen sin modificarlos. El comando regenera derivados en results; guardar otra copia antes de comparar variantes.

Para regenerar únicamente figuras, tablas e informe:

    python experiments/pcap_analysis/report_followup.py

## Archivos

- `audit_pcaps.py`: procedencia, agrupamiento literal de bytes de red y exportación TShark con dos pasadas y resolución de nombres desactivada.
- `decode_inner.py`: parser con comprobaciones de longitud; verificación contra TShark y Scapy. Recupera cabeceras completas de cuerpos parciales; no reconstruye contenido ausente.
- `evaluate_recovery.py`: dos tareas explícitamente separadas, sin identificadores como predictores.
- `validate_followup.py`: reconstrucción de todas las métricas, tres refits, comparación de vectores entre días, controles de etiquetas y subconjuntos.
- `test_decode.py`: cinco pruebas de cabeceras, límites y fragmentos.
- `report_followup.py`: cuatro figuras y tabla LaTeX generadas a partir de resultados guardados; contexto de errores tras STOP.
- `results/run_manifest.json`: hashes, versiones y estado de validación.
- `results/*inner_headers.csv.gz`: cabeceras interiores y trazabilidad al frame original, incluidos indicadores de bytes ausentes.
- `results/*service_annotations.csv`: anotaciones por SNI con exclusiones explícitas. Contienen identificadores locales para auditoría, no usados en el modelo.
- `results/followup_metrics.csv`, `followup_predictions.csv.gz`, `retained_features.csv` y `models/`: 52 comparaciones y sus resultados auditables.
- `results/inner_shift_controls.csv` y `service_shuffled_label_controls.csv`: 60 controles adicionales.

El ZIP de fuentes omite los PCAP derivados y las exportaciones intermedias grandes de TShark; los regenera audit_pcaps.py. Los originales permanecen fuera del proyecto, en recursos. Se incluyen resultados compactos, cabeceras recuperadas, figuras, tablas y código. Los modelos joblib se regeneran y no se distribuyen. Los originales comprimidos están en recursos/; consultar la guía principal y el manifiesto. Esta versión conserva los identificadores de red y no está anonimizada.

## Interpretación obligatoria

El 0,991 de BA corresponde a reconocer el servicio experimental entre conexiones TLS con SNI observado. No equivale a detectar ransomware con 99,1% de rendimiento. La clasificación de períodos sigue teniendo falsas alarmas, confusión temporal y una sola sesión con tiempos verificados. Los dos tipos de etiqueta no se mezclan ni se modifican para aumentar las métricas.

Las IP locales identifican endpoints dentro de cada captura, no una identidad física verificada. El parser distingue el segundo encabezado IP, directamente dentro de GTP, de posibles encabezados adicionales citados por mensajes ICMP.

Referencias de implementación: [TShark](https://www.wireshark.org/docs/man-pages/tshark.html), [reensamblado en Wireshark](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvReassemblySection.html), [3GPP TS 29.281 / ETSI V18.4.0](https://www.etsi.org/deliver/etsi_ts/129200_129299/129281/18.04.00_60/ts_129281v180400p.pdf).
