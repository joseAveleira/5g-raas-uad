# Derivados del CSV original

El CSV original se distribuye comprimido en `recursos/`. `scripts/unpack_resources.py` restaura sus bytes originales y comprueba el SHA-256.

| Archivo | Uso |
|---|---|
| `audit_summary.json` | Hash, tamaño, dimensiones, etiquetas, columnas vacías y límites observados |
| `schema_audit.csv` | Las 85 columnas, tipos de lectura, cobertura, cardinalidad y papel propuesto |
| `protocol_counts.csv` | Presencia de protocolos por etiqueta; las categorías se solapan |
| `temporal_blocks.csv` | Cinco bloques contiguos de etiqueta, con índices y tiempos relativos |
| `row_manifest.csv.gz` | Una entrada por fila original para trazabilidad; no usar sus claves como predictores |
| `feature_plan.json` | Candidatos, exclusiones y comparaciones propuestas |

El campo `unique_non_null` describe todo el fichero para auditarlo, no constituye un selector de variables entrenado. Cualquier filtro/selección usado en una evaluación deberá volver a ajustarse solo en entrenamiento. Los grupos temporales no equivalen a sesiones independientes ni a identificadores de dispositivo.

Algunos campos con un único valor no nulo pueden contribuir solo mediante su presencia/ausencia. `frame_protocols` debe convertirse en indicadores explícitos, omitiendo GTP en el baseline sin GTP. Los campos identificadores se excluyen del plan inicial. Las particiones ejecutadas y su semántica están documentadas en experiments/PROTOCOL.md y experiments/results/features/split_manifest.csv.

El archivo feature_plan.json conserva el plan inicial de preparación. La especificación ejecutada está en experiments/config.json, experiments/PROTOCOL.md y experiments/src/. Los resultados de esa fase están en experiments/results/.
