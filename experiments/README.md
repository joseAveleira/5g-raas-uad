# Experimentos reproducibles: ransomware / 5G

**Actualización con PCAP:** la fase vigente se describe en [pcap_analysis/README.md](pcap_analysis/README.md) y [sus conclusiones](pcap_analysis/CONCLUSIONES_PCAP.md). Esta carpeta también conserva la primera fase basada en el CSV; los comandos siguientes reproducen esa fase.

Esta carpeta contiene el estudio ejecutable del dataset: auditoría, características por ventanas, clasificación temporal, selección de variables, ablación GTP, controles y sensibilidad. El CSV original se lee sin modificarlo.

## Ejecutar

Desde la raíz del proyecto LaTeX:

    python -m pip install -r experiments/requirements-lock.txt
    python -m unittest discover -s experiments/tests -v
    python experiments/run_experiments.py --input recursos/ransomware_dataset.csv

Para un entorno aislado, crear antes un venv con Python 3.13 y utilizar su ejecutable. Las bibliotecas necesarias ya estaban instaladas en el equipo durante la ejecución de referencia; no hizo falta descargar herramientas adicionales.

La ruta de salida predeterminada es experiments/results. Una nueva ejecución regenera los derivados en esa carpeta. Usar --output para conservar otra ejecución, o --config para una variante explícita. Conservar todas las configuraciones y no elegir la mejor puntuación de test.

## Lectura recomendada

1. CONCLUSIONES.md: interpretación de los resultados y propuesta para el artículo.
2. results/RESULTS.md: informe completo con las tablas de todas las comparaciones.
3. PROTOCOL.md: decisiones metodológicas y límites.
4. results/figures/: siete figuras PDF/PNG.
5. results/run_manifest.json: hashes del dato, configuración y código, versiones y ajustes ejecutados.

## Contenido

- config.json: parámetros fijados para la ejecución.
- run_experiments.py: entrada única que genera el estudio completo.
- src/data.py: lectura, candidatos a repetición, representación y separación temporal.
- src/evaluation.py: pipelines de entrenamiento y métricas.
- src/reporting.py: informes, figuras y tabla LaTeX.
- tests/test_protocol.py: pruebas sobre agrupación, exclusión temporal y transformaciones.
- results/audit/: diccionario, repeticiones, redundancia, visibilidad y túneles.
- results/features/: matrices por ventana y manifiestos de partición.
- results/metrics/: resultados completos, importancia y selección.
- results/predictions/: predicciones auditables por registro o ventana.
- results/models/: modelos de las comparaciones principales.

Los modelos joblib no se distribuyen en esta versión pública; se regeneran al ejecutar el estudio. No cargar modelos de fuentes desconocidas.

## Semántica de los datos

Una etiqueta positiva significa que el registro pertenece a un período de ejecución. No demuestra que el paquete sea malicioso. Solo hay una sesión y dos ejecuciones; ninguna cantidad de particiones convierte eso en un benchmark externo.

El agrupamiento de campos coincidentes a menos de 1 ms identifica posibles observaciones repetidas. No sustituye una comparación de bytes del PCAP. Los registros UDP con MF activado no se atribuyen automáticamente a GTP. Estas limitaciones forman parte del análisis y de las comparaciones.
