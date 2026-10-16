# Protocolo de análisis

Diseño exploratorio fijado antes de observar las puntuaciones de clasificación. La estructura del CSV y los análisis descriptivos previos informaron el diseño; no es un estudio prerregistrado ni una evaluación externa ciega.

## Unidad y separación

- Unidad principal: ventanas temporales de 2 segundos, no solapadas, ancladas al primer timestamp del CSV.
- Sensibilidad: ventanas de 1 y 5 segundos. No se selecciona una duración por su mejor resultado.
- Se omiten bins sin registros, el bin final incompleto y bins que intersectan el intervalo entre observaciones consecutivas de etiquetas distintas. No se imputan etiquetas durante huecos.
- El corte temporal es el punto medio entre el último registro de la primera ejecución y el primer baseline posterior. Se descartan 5 segundos a cada lado.
- Entrenamiento principal: parte temprana, con ambas clases. Prueba: parte tardía, con ambas clases y segunda ejecución.
- Dirección inversa: diagnóstico de transferencia entre partes de la captura; no predicción prospectiva ni réplica independiente.

## Candidatos a repetición

Hash de todos los campos originales salvo número de trama, timestamps, deltas temporales, SLL packet type, etiqueta y clase textual. Se agrupan valores coincidentes a menos de 1 ms del primer registro del grupo. El anclaje impide que una cadena de pequeños intervalos forme grupos arbitrariamente largos. La etiqueta se consulta después para detectar conflictos; no participa en la agrupación.

Se utiliza un representante por grupo en el análisis principal. Se informa sensibilidad a 10/100/1000 microsegundos y se repite la comparación central con todas las filas originales. No se certifica igualdad de bytes de paquetes ni se reescribe el CSV.

## Representación

Volumen/tiempo: tasa de registros y bytes; momentos de longitud, fracciones de tramas pequeñas y grandes, entropía en bins de tamaño fijos; momentos de intervalos entre llegadas dentro de cada ventana y fracción inferior a 1 ms.

Red: volumen/tiempo más fracciones de TCP, QUIC, TLS, DNS, HTTP, SCTP y NGAP; estadísticas de longitud TCP, ventana TCP y longitud QUIC; proporciones de flags TCP, formato de cabecera QUIC y respuestas DNS; presencia de handshake TLS.

GTP: presencia del protocolo decodificado y momentos de gtp_length condicionados a su disponibilidad. El valor bruto TEID no es predictor. Los campos constantes message/flags no añaden predictores redundantes.

Contexto de fragmentación: fracción de registros y bytes con la pila IP:data, protocolo IP 17 y MF activado. No se reconstruyen fragmentos ni se adivina su túnel.

Ocho conjuntos: volumen; red; red + presencia GTP; red + campos GTP; red + GTP + fragmentos; GTP solo; selección de 5; selección de 10. Las dos selecciones parten del conjunto completo y se ajustan solo en entrenamiento. Se utiliza además un clasificador de clase mayoritaria.

Direcciones, IP, TEID bruto, puertos, IDs, secuencias/checksums, nombres de endpoints, números de fila y tiempo absoluto no entran en las matrices de clasificación válidas. Los índices y tiempos aparecen solo en manifiestos y gráficos para trazabilidad.

## Modelos y transformaciones

Regresión logística: C=1, clases balanceadas, máximo 5000 iteraciones. Random forest: 200 árboles, profundidad máxima 8, mínimo 2 muestras/hoja, clases balanceadas. Semilla principal 42; sensibilidad de forest con 17 y 73 en los casos predefinidos.

Mediana de entrenamiento para imputar, eliminación de constantes de entrenamiento, escalado con entrenamiento y selección por información mutua cuando corresponde. No hay búsqueda de hiperparámetros. Umbral de decisión 0,5.

BA, precisión, recall, F1, ROC-AUC, average precision y matriz de confusión se guardan junto con soporte por clase, variables retenidas y tiempos de ajuste/inferencia. Los tiempos dependen del equipo y carga del proceso.

## Controles y análisis complementarios

- Repetición de la evaluación en GTP decodificado: cambia la población; ayuda a separar visibilidad de protocolos y representación.
- Partición aleatoria por paquete, aleatoria por grupo candidato y temporal: diagnósticos, no estimadores equivalentes de generalización.
- Árbol que usa solo tiempo: control deliberadamente inválido como detector, destinado a mostrar cómo la etiqueta temporal puede memorizarse.
- Desplazamientos circulares de etiquetas de entrenamiento: control descriptivo conservando soporte y estructura serial; no se calcula p-valor.
- Importancia por permutación en test: interpretación posterior, nunca elección de variables o hiperparámetros.
- Estabilidad de las selecciones temprana/tardía: intersección y Jaccard.
- Actividad por TEID, usando alias locales para las figuras: no se infieren dispositivos.

## Límites estadísticos

Los bloques y ventanas siguen dependiendo de una única captura. No se construyen intervalos de confianza tratando paquetes o ventanas como ejecuciones independientes. Las diferencias entre modelos y particiones son descriptivas. La contribución demostrable es análisis de este recurso y un procedimiento reproducible; las afirmaciones de generalización requieren más sesiones y un test externo.

Referencias: Arp et al., “Dos and Don'ts of Machine Learning in Computer Security”, USENIX Security 2022, https://www.usenix.org/conference/usenixsecurity22/presentation/arp; documentación de scikit-learn sobre fuga de información, https://scikit-learn.org/stable/common_pitfalls.html.
